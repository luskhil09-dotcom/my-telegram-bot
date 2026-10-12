# -*- coding: utf-8 -*-
"""
5VITO - Telegram-бот продажи ключей + сервер лицензий (HWID).

Запуск:  python bot.py
Первый запуск создаст config.json (заполни bot_token и admin_ids) и private_key.pem.
В консоли будет напечатан PUBLIC KEY - вставь его в license_client.py (PUBLIC_KEY_B64).
Сервер лицензий слушает POST /auth (ставь за nginx/Caddy с HTTPS).
"""
import asyncio
import base64
import html
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import time
from collections import defaultdict
from datetime import datetime

from aiohttp import web
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandObject, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import CallbackQuery, InlineKeyboardButton as Btn, InlineKeyboardMarkup, Message
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE = os.path.dirname(os.path.abspath(__file__))
CFG_PATH = os.path.join(BASE, "config.json")
DB_PATH = os.path.join(BASE, "licenses.db")
KEY_PATH = os.path.join(BASE, "private_key.pem")

DEFAULT_CFG = {
    "bot_token": "8941140024:AAEomR-etDXuVWA2-WXr9BbTNPaNvJ5mT9s",
    "admin_ids": [7959651951],
    "host": "127.0.0.1",
    "port": 8080,
    "support_username": "",
    "token_ttl_hours": 6,
    "max_hwid_resets": 2,
}
if not os.path.exists(CFG_PATH):
    with open(CFG_PATH, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_CFG, f, indent=2, ensure_ascii=False)
    print("Создан config.json - заполни bot_token и admin_ids и запусти снова.")
    sys.exit(1)
with open(CFG_PATH, encoding="utf-8") as f:
    CFG = {**DEFAULT_CFG, **json.load(f)}
ADMINS = set(int(x) for x in CFG["admin_ids"])
TTL = int(CFG["token_ttl_hours"]) * 3600

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
DEFAULT_PAYMENT = ("Оплата: <b>укажи реквизиты</b> (карта / USDT).\n"
                   "После оплаты нажми «Я оплатил» - админ проверит и выдаст ключ.")

# ============================ КЛЮЧИ ПОДПИСИ ============================
if os.path.exists(KEY_PATH):
    with open(KEY_PATH, "rb") as f:
        PRIV = serialization.load_pem_private_key(f.read(), password=None)
else:
    PRIV = Ed25519PrivateKey.generate()
    with open(KEY_PATH, "wb") as f:
        f.write(PRIV.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    try:
        os.chmod(KEY_PATH, 0o600)
    except OSError:
        pass
PUB_B64 = base64.b64encode(PRIV.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ============================ БАЗА ДАННЫХ ============================
SCHEMA = """
CREATE TABLE IF NOT EXISTS products(
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, days INTEGER, price TEXT, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS keys(
    key TEXT PRIMARY KEY, days INTEGER, product_id INTEGER, buyer_id INTEGER, hwid TEXT,
    activated_at INTEGER, expires_at INTEGER, revoked INTEGER DEFAULT 0,
    resets INTEGER DEFAULT 0, created_at INTEGER);
CREATE TABLE IF NOT EXISTS orders(
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT,
    product_id INTEGER, status TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
"""


def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def q(sql, args=(), one=False):
    c = db()
    try:
        cur = c.execute(sql, args)
        r = cur.fetchone() if one else cur.fetchall()
        c.commit()
        return r
    finally:
        c.close()


def ex(sql, args=()):
    c = db()
    try:
        cur = c.execute(sql, args)
        c.commit()
        return cur.lastrowid
    finally:
        c.close()


RESET_PRODUCT_NAME = "Сброс HWID"
RESET_PRODUCT_PRICE = "150 ₽"


def ensure_reset_product():
    """Гарантируем, что товар «Сброс HWID» существует и активен."""
    r = q("SELECT * FROM products WHERE name=?", (RESET_PRODUCT_NAME,), one=True)
    if r:
        ex("UPDATE products SET active=1 WHERE id=?", (r["id"],))
        return r["id"]
    return ex("INSERT INTO products(name, days, price, active) VALUES (?,?,?,1)",
              (RESET_PRODUCT_NAME, 0, RESET_PRODUCT_PRICE))


def init_db():
    c = db()
    c.executescript(SCHEMA)
    if not c.execute("SELECT 1 FROM products").fetchone():
        c.executemany("INSERT INTO products(name, days, price) VALUES (?,?,?)",
                      [("Ключ на 1 день", 1, "100 ₽"), ("Ключ на 7 дней", 7, "350 ₽"),
                       ("Ключ на 30 дней", 30, "900 ₽")])
    if not c.execute("SELECT 1 FROM settings WHERE k='prices_v2'").fetchone():
        for days, price in ((1, "100 ₽"), (7, "350 ₽"), (30, "900 ₽")):
            c.execute("UPDATE products SET price=? WHERE days=?", (price, days))
        c.execute("INSERT INTO settings(k,v) VALUES('prices_v2','1')")
    c.commit()
    c.close()
    ensure_reset_product()


def get_setting(k, default=""):
    r = q("SELECT v FROM settings WHERE k=?", (k,), one=True)
    return r["v"] if r else default


def set_setting(k, v):
    ex("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))


def new_key(days, product_id=None, buyer_id=None):
    for _ in range(20):
        k = "5V-" + "-".join("".join(secrets.choice(ALPHABET) for _ in range(4)) for _ in range(3))
        try:
            ex("INSERT INTO keys(key,days,product_id,buyer_id,created_at) VALUES (?,?,?,?,?)",
               (k, days, product_id, buyer_id, int(time.time())))
            return k
        except sqlite3.IntegrityError:
            continue
    raise RuntimeError("не удалось создать ключ")


def esc(s):
    return html.escape(str(s))


def fmt(ts):
    return datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M")


def key_status(r):
    now = int(time.time())
    if r["revoked"]:
        return "⛔ отозван"
    if not r["activated_at"]:
        return f"🆕 не активирован ({r['days']} дн.)"
    left = r["expires_at"] - now
    if left <= 0:
        return "⌛ истёк"
    return f"✅ до {fmt(r['expires_at'])} (ещё {left // 86400} д {left % 86400 // 3600} ч)"


def is_reset_order(o, p):
    return bool(p) and p["name"] == RESET_PRODUCT_NAME


def do_reset_hwid(key):
    """Сбросить HWID ключа, сохранив остаток срока. Возвращает True/False."""
    r = q("SELECT * FROM keys WHERE key=?", (key,), one=True)
    if not r:
        return False
    if r["expires_at"]:
        left_days = max(1, round((r["expires_at"] - time.time()) / 86400))
    else:
        left_days = r["days"]
    ex("UPDATE keys SET hwid=NULL, activated_at=NULL, expires_at=NULL, days=?, resets=resets+1 WHERE key=?",
       (left_days, key))
    return True


# ============================ СЕРВЕР ЛИЦЕНЗИЙ ============================
def auth(key, hwid):
    now = int(time.time())
    c = db()
    try:
        c.execute("BEGIN IMMEDIATE")
        r = c.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
        if not r:
            return {"ok": False, "error": "invalid_key"}
        if r["revoked"]:
            return {"ok": False, "error": "revoked"}
        if r["hwid"] and r["hwid"] != hwid:
            return {"ok": False, "error": "hwid_mismatch"}
        if r["expires_at"] and r["expires_at"] <= now:
            return {"ok": False, "error": "expired"}
        exp = r["expires_at"]
        if not r["hwid"]:
            exp = now + r["days"] * 86400
            c.execute("UPDATE keys SET hwid=?, activated_at=?, expires_at=? WHERE key=?",
                      (hwid, now, exp, key))
        c.commit()
    finally:
        c.close()
    payload = {"key": key, "hwid": hwid, "exp": exp, "iat": now, "chk": now + TTL}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    token = b64u(raw) + "." + b64u(PRIV.sign(raw))
    return {"ok": True, "token": token}


FAILS = defaultdict(list)


async def h_auth(request):
    ip = (request.headers.get("X-Forwarded-For") or request.remote or "?").split(",")[0].strip()
    now = time.time()
    FAILS[ip] = [t for t in FAILS[ip] if now - t < 600]
    if len(FAILS[ip]) >= 30:
        return web.json_response({"ok": False, "error": "rate_limited"}, status=429)
    try:
        data = await request.json()
        key = str(data["key"]).strip().upper()
        hwid = str(data["hwid"]).strip().lower()
        if len(key) > 40 or not re.fullmatch(r"[0-9a-f]{32}", hwid):
            raise ValueError
    except Exception:
        return web.json_response({"ok": False, "error": "bad_request"}, status=400)
    res = auth(key, hwid)
    if not res["ok"]:
        FAILS[ip].append(now)
    return web.json_response(res)


async def h_health(request):
    return web.json_response({"ok": True})


# ============================ БОТ: общее ============================
def kb(*rows):
    return InlineKeyboardMarkup(inline_keyboard=[list(r) for r in rows])


def b(text, data):
    return Btn(text=text, callback_data=data)


async def show(ev, text, markup=None):
    if isinstance(ev, CallbackQuery):
        try:
            await ev.message.edit_text(text, reply_markup=markup)
        except TelegramBadRequest as e:
            if "not modified" not in str(e):
                await ev.message.answer(text, reply_markup=markup)
        await ev.answer()
    else:
        await ev.answer(text, reply_markup=markup)


async def append_note(msg: Message, note: str):
    new = (msg.html_text or "") + note
    if msg.text:
        await msg.edit_text(new)
    else:
        await msg.edit_caption(caption=new)


class Proof(StatesGroup):
    photo = State()


user = Router()
admin = Router()
admin.message.filter(F.from_user.id.in_(ADMINS))
admin.callback_query.filter(F.from_user.id.in_(ADMINS))


def main_menu(uid):
    rows = [[b("🛒 Товары", "shop")], [b("🔑 Мои ключи", "mykeys")]]
    if CFG.get("support_username"):
        rows.append([Btn(text="💬 Поддержка", url=f"https://t.me/{CFG['support_username'].lstrip('@')}")])
    if uid in ADMINS:
        rows.append([b("🛠 Админ-панель", "adm")])
    return kb(*rows)


# ============================ БОТ: покупатель ============================
@user.message(CommandStart())
async def cmd_start(m: Message, state: FSMContext):
    await state.clear()
    await m.answer("<b>5VITO</b>\nМагазин ключей. Выбери действие:", reply_markup=main_menu(m.from_user.id))


@user.callback_query(F.data == "menu")
async def cb_menu(cq: CallbackQuery, state: FSMContext):
    await state.clear()
    await show(cq, "<b>5VITO</b>\nМагазин ключей. Выбери действие:", main_menu(cq.from_user.id))


@user.callback_query(F.data == "shop")
async def cb_shop(cq: CallbackQuery):
    await show(cq, "<b>Товары</b>\nВыбери категорию:",
               kb([b("🤖 AutoBuy", "autobuy")], [b("⬅ Назад", "menu")]))


@user.callback_query(F.data == "autobuy")
async def cb_autobuy(cq: CallbackQuery):
    prods = q("SELECT * FROM products WHERE active=1 ORDER BY days")
    if not prods:
        await show(cq, "Товаров пока нет.", kb([b("⬅ Назад", "shop")]))
        return
    text = "<b>AutoBuy</b>\n\n" + "\n".join(
        f"• <b>{esc(p['name'])}</b> - {esc(p['price'])}" +
        (f"  ({p['days']} дн.)" if p["days"] else "") for p in prods)
    rows = [[b(f"Купить · {p['name']} · {p['price']}", f"buy:{p['id']}")] for p in prods]
    rows.append([b("⬅ Назад", "shop")])
    await show(cq, text, kb(*rows))


@user.callback_query(F.data.startswith("buy:"))
async def cb_buy(cq: CallbackQuery):
    p = q("SELECT * FROM products WHERE id=? AND active=1", (int(cq.data[4:]),), one=True)
    if not p:
        await cq.answer("Товар недоступен", show_alert=True)
        return
    oid = ex("INSERT INTO orders(user_id,username,product_id,status,created_at) VALUES (?,?,?,?,?)",
             (cq.from_user.id, cq.from_user.username or "", p["id"], "new", int(time.time())))
    text = (f"<b>Заказ №{oid}</b>\n{esc(p['name'])} - {esc(p['price'])}\n\n"
            f"{get_setting('payment_text', DEFAULT_PAYMENT)}")
    await show(cq, text, kb([b("✅ Я оплатил", f"paid:{oid}")], [b("⬅ Назад", "autobuy")]))


@user.callback_query(F.data.startswith("paid:"))
async def cb_paid(cq: CallbackQuery, state: FSMContext):
    oid = int(cq.data[5:])
    o = q("SELECT * FROM orders WHERE id=? AND user_id=?", (oid, cq.from_user.id), one=True)
    if not o or o["status"] != "new":
        await cq.answer("Заказ уже обработан", show_alert=True)
        return
    await state.set_state(Proof.photo)
    await state.update_data(oid=oid)
    await show(cq, f"📸 Отправь <b>скриншот или чек</b> оплаты заказа №{oid} "
                   f"одним сообщением (фото или файл).",
               kb([b("❌ Отмена", "menu")]))


@user.message(Proof.photo, F.photo | F.document)
async def msg_proof(m: Message, state: FSMContext):
    d = await state.get_data()
    oid = d.get("oid")
    o = q("SELECT * FROM orders WHERE id=? AND user_id=?", (oid, m.from_user.id), one=True)
    if not o or o["status"] != "new":
        await state.clear()
        await m.answer("Заказ уже обработан.", reply_markup=kb([b("⬅ В меню", "menu")]))
        return
    ex("UPDATE orders SET status='paid' WHERE id=?", (oid,))
    p = q("SELECT * FROM products WHERE id=?", (o["product_id"],), one=True)
    who = f"@{m.from_user.username}" if m.from_user.username else f"id {m.from_user.id}"
    extra = ""
    if is_reset_order(o, p):
        extra = f"\n\n♻️ <b>Сброс HWID</b> (ключ покупателя будет разблокирован после подтверждения)"
    caption = (f"💰 <b>Заказ №{oid}</b> ожидает проверки\n{esc(who)} (id {m.from_user.id})\n"
               f"{esc(p['name'])} - {esc(p['price'])}{extra}")
    markup = kb([b("✅ Выдать ключ", f"ok:{oid}"), b("❌ Отклонить", f"no:{oid}")])
    for aid in ADMINS:
        try:
            if m.photo:
                await m.bot.send_photo(aid, m.photo[-1].file_id, caption=caption, reply_markup=markup)
            else:
                await m.bot.send_document(aid, m.document.file_id, caption=caption, reply_markup=markup)
        except Exception:
            logging.exception("не удалось уведомить админа %s", aid)
    await state.clear()
    await m.answer(f"Скрин получен. Заказ №{oid} отправлен на проверку.",
                   reply_markup=kb([b("⬅ В меню", "menu")]))


@user.message(Proof.photo)
async def msg_proof_bad(m: Message):
    await m.answer("Нужно отправить именно <b>фото или файл</b> с подтверждением оплаты.")


def my_keys_view(uid):
    rows_db = q("SELECT * FROM keys WHERE buyer_id=? ORDER BY created_at DESC LIMIT 10", (uid,))
    if not rows_db:
        return "У тебя пока нет ключей.", kb([b("⬅ Назад", "menu")])
    text = "<b>Мои ключи</b>\n\n" + "\n\n".join(
        f"<code>{r['key']}</code>\n{key_status(r)}" for r in rows_db)
    reset_prod = q("SELECT * FROM products WHERE name=? AND active=1", (RESET_PRODUCT_NAME,), one=True)
    rows = []
    for r in rows_db:
        if r["hwid"] and not r["revoked"]:
            label = (f"♻️ Сбросить HWID · {esc(reset_prod['price'])}"
                     if reset_prod else "♻️ Сбросить HWID")
            rows.append([b(label, f"rst:{r['key']}")])
    rows.append([b("⬅ Назад", "menu")])
    text += "\n\n♻️ Сброс привязки к ПК — платная услуга, оформляется как заказ."
    return text, kb(*rows)


@user.callback_query(F.data == "mykeys")
async def cb_mykeys(cq: CallbackQuery):
    text, markup = my_keys_view(cq.from_user.id)
    await show(cq, text, markup)


@user.callback_query(F.data.startswith("rst:"))
async def cb_reset_request(cq: CallbackQuery):
    """Покупатель нажал «Сбросить HWID» — создаём заказ на платную услугу."""
    k = cq.data[4:]
    r = q("SELECT * FROM keys WHERE key=? AND buyer_id=?", (k, cq.from_user.id), one=True)
    if not r or r["revoked"]:
        await cq.answer("Недоступно", show_alert=True)
        return
    if not r["hwid"]:
        await cq.answer("Ключ ещё не активирован — сброс не нужен.", show_alert=True)
        return
    reset_prod = q("SELECT * FROM products WHERE name=? AND active=1", (RESET_PRODUCT_NAME,), one=True)
    if not reset_prod:
        await cq.answer("Услуга сброса временно недоступна.", show_alert=True)
        return
    oid = ex("INSERT INTO orders(user_id,username,product_id,status,created_at) VALUES (?,?,?,?,?)",
             (cq.from_user.id, cq.from_user.username or "", reset_prod["id"], "new", int(time.time())))
    text = (f"<b>Заказ №{oid}</b>\n{esc(reset_prod['name'])} для ключа <code>{k}</code>\n"
            f"Цена: {esc(reset_prod['price'])}\n\n"
            f"{get_setting('payment_text', DEFAULT_PAYMENT)}\n\n"
            f"⚠️ После оплаты админ подтвердит заказ — и HWID ключа <code>{k}</code> "
            f"будет сброшен, ключ можно будет активировать заново на этом же ПК или на новом.")
    await show(cq, text, kb([b("✅ Я оплатил", f"paid:{oid}")], [b("⬅ Назад", "mykeys")]))


# ============================ БОТ: админ ============================
class AddProduct(StatesGroup):
    name = State()
    days = State()
    price = State()


class EditField(StatesGroup):
    value = State()


class SetPayment(StatesGroup):
    text = State()


class AddDays(StatesGroup):
    value = State()


def admin_menu():
    pending_reset = q(
        "SELECT COUNT(*) n FROM orders o JOIN products p ON p.id=o.product_id "
        "WHERE o.status='paid' AND p.name=?", (RESET_PRODUCT_NAME,), one=True)["n"]
    reset_label = f"♻️ HWID-запросы ({pending_reset})" if pending_reset else "♻️ HWID-запросы"
    return kb([b("📦 Товары", "a_prod")],
              [b("🔑 Сгенерировать ключи", "a_gen")],
              [b("📋 Последние ключи", "a_keys")],
              [b(reset_label, "a_resets")],
              [b("💳 Текст оплаты", "a_pay"), b("📊 Статистика", "a_stat")],
              [b("⬅ Назад", "menu")])


@admin.message(Command("admin"))
async def cmd_admin(m: Message, state: FSMContext):
    await state.clear()
    await m.answer("<b>Админ-панель</b>", reply_markup=admin_menu())


@admin.message(Command("cancel"))
async def cmd_cancel(m: Message, state: FSMContext):
    await state.clear()
    await m.answer("Отменено.", reply_markup=admin_menu())


@admin.callback_query(F.data == "adm")
async def cb_adm(cq: CallbackQuery, state: FSMContext):
    await state.clear()
    await show(cq, "<b>Админ-панель</b>", admin_menu())


# ---- товары ----
@admin.callback_query(F.data == "a_prod")
async def cb_products(cq: CallbackQuery):
    prods = q("SELECT * FROM products ORDER BY days")
    rows = [[b(f"{'✅' if p['active'] else '🚫'} {p['name']} · "
               f"{str(p['days']) + 'д · ' if p['days'] else ''}{p['price']}", f"ap:{p['id']}")]
            for p in prods]
    rows += [[b("➕ Добавить товар", "ap_new")], [b("⬅ Назад", "adm")]]
    await show(cq, "<b>Товары</b>\nНажми на товар, чтобы изменить.", kb(*rows))


def product_card(pid):
    p = q("SELECT * FROM products WHERE id=?", (pid,), one=True)
    if not p:
        return "Товар не найден.", kb([b("⬅ Назад", "a_prod")])
    text = (f"<b>{esc(p['name'])}</b>\nСрок: {p['days']} дн.\nЦена: {esc(p['price'])}\n"
            f"Статус: {'в продаже' if p['active'] else 'скрыт'}")
    return text, kb([b("✏️ Название", f"pe:{pid}:name"), b("📅 Дни", f"pe:{pid}:days"),
                     b("💰 Цена", f"pe:{pid}:price")],
                    [b("🚫 Скрыть" if p["active"] else "✅ Показать", f"pt:{pid}"),
                     b("🗑 Удалить", f"pd:{pid}")],
                    [b("⬅ Назад", "a_prod")])


@admin.callback_query(F.data.startswith("ap:"))
async def cb_product(cq: CallbackQuery):
    text, markup = product_card(int(cq.data[3:]))
    await show(cq, text, markup)


@admin.callback_query(F.data.startswith("pt:"))
async def cb_toggle(cq: CallbackQuery):
    pid = int(cq.data[3:])
    ex("UPDATE products SET active=1-active WHERE id=?", (pid,))
    text, markup = product_card(pid)
    await show(cq, text, markup)


@admin.callback_query(F.data.startswith("pd:"))
async def cb_delete(cq: CallbackQuery):
    pid = cq.data[3:]
    if pid.endswith(":y"):
        ex("DELETE FROM products WHERE id=?", (int(pid[:-2]),))
        await cq.answer("Удалено")
        await cb_products(cq)
        return
    await show(cq, "Удалить товар? Выданные ключи останутся рабочими.",
               kb([b("🗑 Да, удалить", f"pd:{pid}:y"), b("Отмена", f"ap:{pid}")]))


@admin.callback_query(F.data.startswith("pe:"))
async def cb_edit(cq: CallbackQuery, state: FSMContext):
    _, pid, field = cq.data.split(":")
    await state.set_state(EditField.value)
    await state.update_data(pid=int(pid), field=field)
    hint = {"name": "новое название", "days": "число дней (целое, 0 для услуг)",
            "price": "цену (текстом, напр. 150 ₽)"}[field]
    await show(cq, f"Отправь {hint}.\n/cancel - отмена")


@admin.message(EditField.value)
async def msg_edit(m: Message, state: FSMContext):
    d = await state.get_data()
    val = (m.text or "").strip()
    if d["field"] == "days":
        if not val.isdigit():
            await m.answer("Нужно целое число дней (0 допустимо для услуг).")
            return
        val = int(val)
    if not val and d["field"] != "days":
        await m.answer("Пусто, попробуй ещё раз.")
        return
    ex(f"UPDATE products SET {d['field']}=? WHERE id=?", (val, d["pid"]))
    await state.clear()
    text, markup = product_card(d["pid"])
    await m.answer(text, reply_markup=markup)


@admin.callback_query(F.data == "ap_new")
async def cb_new(cq: CallbackQuery, state: FSMContext):
    await state.set_state(AddProduct.name)
    await show(cq, "Новый товар. Отправь <b>название</b>.\n/cancel - отмена")


@admin.message(AddProduct.name)
async def add_name(m: Message, state: FSMContext):
    await state.update_data(name=(m.text or "").strip())
    await state.set_state(AddProduct.days)
    await m.answer("На сколько <b>дней</b> ключ? (число, 0 для услуг)")


@admin.message(AddProduct.days)
async def add_days(m: Message, state: FSMContext):
    t = (m.text or "").strip()
    if not t.isdigit():
        await m.answer("Нужно целое число дней (0 для услуг).")
        return
    await state.update_data(days=int(t))
    await state.set_state(AddProduct.price)
    await m.answer("Какая <b>цена</b>? (текстом, напр. 150 ₽)")


@admin.message(AddProduct.price)
async def add_price(m: Message, state: FSMContext):
    d = await state.get_data()
    pid = ex("INSERT INTO products(name,days,price) VALUES (?,?,?)",
             (d["name"], d["days"], (m.text or "").strip()))
    await state.clear()
    text, markup = product_card(pid)
    await m.answer("Товар добавлен ✅\n\n" + text, reply_markup=markup)


# ---- генерация ключей ----
@admin.callback_query(F.data == "a_gen")
async def cb_gen(cq: CallbackQuery):
    prods = q("SELECT * FROM products WHERE days>0 ORDER BY days")
    rows = [[b(f"{p['name']} ({p['days']}д)", f"ag:{p['id']}")] for p in prods]
    rows.append([b("⬅ Назад", "adm")])
    await show(cq, "Выбери товар, для которого сгенерировать ключи.\n"
                   "Свой срок: <code>/genkey дни [кол-во]</code>", kb(*rows))


@admin.callback_query(F.data.startswith("ag:"))
async def cb_gen_qty(cq: CallbackQuery):
    pid = cq.data[3:]
    await show(cq, "Сколько ключей?",
               kb([b(str(n), f"agq:{pid}:{n}") for n in (1, 5, 10, 25)], [b("⬅ Назад", "a_gen")]))


@admin.callback_query(F.data.startswith("agq:"))
async def cb_gen_do(cq: CallbackQuery):
    _, pid, n = cq.data.split(":")
    p = q("SELECT * FROM products WHERE id=?", (int(pid),), one=True)
    if not p:
        await cq.answer("Товар не найден", show_alert=True)
        return
    keys = [new_key(p["days"], p["id"]) for _ in range(int(n))]
    await cq.message.answer(f"<b>{esc(p['name'])}</b> - {len(keys)} шт.\n\n" +
                            "\n".join(f"<code>{k}</code>" for k in keys))
    await cq.answer("Готово")


@admin.message(Command("genkey"))
async def cmd_genkey(m: Message, command: CommandObject):
    parts = (command.args or "").split()
    if not parts or not parts[0].isdigit() or int(parts[0]) < 1:
        await m.answer("Использование: <code>/genkey дни [кол-во]</code>")
        return
    days = int(parts[0])
    n = min(50, int(parts[1])) if len(parts) > 1 and parts[1].isdigit() else 1
    keys = [new_key(days) for _ in range(n)]
    await m.answer(f"Ключи на {days} дн.:\n\n" + "\n".join(f"<code>{k}</code>" for k in keys))


# ---- добавление дней любому ключу ----
@admin.message(Command("adddays"))
async def cmd_adddays(m: Message, command: CommandObject):
    parts = (command.args or "").split()
    if len(parts) != 2 or not parts[1].lstrip("-").isdigit():
        await m.answer("Использование: <code>/adddays КЛЮЧ ДНИ</code>\n"
                       "Например: <code>/adddays 5V-XXXX-XXXX-XXXX 30</code>\n"
                       "Дни можно указывать отрицательными, чтобы отнять.")
        return
    key = parts[0].strip().upper()
    delta = int(parts[1])
    r = q("SELECT * FROM keys WHERE key=?", (key,), one=True)
    if not r:
        await m.answer("Ключ не найден.")
        return
    if r["expires_at"]:
        new_exp = max(int(time.time()), r["expires_at"] + delta * 86400)
        ex("UPDATE keys SET expires_at=? WHERE key=?", (new_exp, key))
    else:
        new_days = max(0, r["days"] + delta)
        ex("UPDATE keys SET days=? WHERE key=?", (new_days, key))
    r2 = q("SELECT * FROM keys WHERE key=?", (key,), one=True)
    await m.answer(f"Ключ <code>{key}</code> обновлён.\n\n{key_status(r2)}")
    if r["buyer_id"]:
        try:
            await m.bot.send_message(r["buyer_id"],
                                     f"🎁 Администратор изменил срок действия ключа <code>{key}</code> "
                                     f"на {delta:+d} дн.\n\n{key_status(r2)}")
        except Exception:
            pass


# ---- выдача по заказам ----
@admin.callback_query(F.data.startswith("ok:"))
async def cb_order_ok(cq: CallbackQuery):
    oid = int(cq.data[3:])
    o = q("SELECT * FROM orders WHERE id=?", (oid,), one=True)
    if not o or o["status"] not in ("new", "paid"):
        await cq.answer("Заказ уже обработан", show_alert=True)
        return
    p = q("SELECT * FROM products WHERE id=?", (o["product_id"],), one=True)

    # --- Заказ на сброс HWID ---
    if is_reset_order(o, p):
        # ищем ключ покупателя: сначала по активному HWID-ключу, берём самый свежий
        r = q("SELECT * FROM keys WHERE buyer_id=? AND revoked=0 AND hwid IS NOT NULL "
              "ORDER BY created_at DESC LIMIT 1", (o["user_id"],), one=True)
        if not r:
            await cq.answer("У покупателя нет активного привязанного ключа", show_alert=True)
            return
        do_reset_hwid(r["key"])
        ex("UPDATE orders SET status='done' WHERE id=?", (oid,))
        await cq.bot.send_message(
            o["user_id"],
            f"✅ Оплата заказа №{oid} подтверждена!\n\n"
            f"♻️ HWID ключа <code>{r['key']}</code> сброшен. "
            f"Теперь ключ можно активировать заново на любом ПК — просто введи его при запуске.")
        await append_note(cq.message,
                          f"\n\n✅ HWID ключа <code>{r['key']}</code> сброшен")
        await cq.answer()
        return

    # --- Обычный заказ на ключ ---
    if not p or p["days"] <= 0:
        await cq.answer("Товар не найден или не является ключом", show_alert=True)
        return
    key = new_key(p["days"], p["id"], o["user_id"])
    ex("UPDATE orders SET status='done' WHERE id=?", (oid,))
    await cq.bot.send_message(o["user_id"], f"✅ Оплата подтверждена!\n\nТвой ключ ({esc(p['name'])}):\n"
                                            f"<code>{key}</code>\n\nВведи его при запуске программы.")
    await append_note(cq.message, f"\n\n✅ Выдан ключ <code>{key}</code>")
    await cq.answer()


@admin.callback_query(F.data.startswith("no:"))
async def cb_order_no(cq: CallbackQuery):
    oid = int(cq.data[3:])
    o = q("SELECT * FROM orders WHERE id=?", (oid,), one=True)
    if not o or o["status"] not in ("new", "paid"):
        await cq.answer("Заказ уже обработан", show_alert=True)
        return
    ex("UPDATE orders SET status='rejected' WHERE id=?", (oid,))
    await cq.bot.send_message(o["user_id"], f"❌ Заказ №{oid} отклонён. Если это ошибка - напиши в поддержку.")
    await append_note(cq.message, "\n\n❌ Отклонён")
    await cq.answer()


# ---- HWID-запросы ----
@admin.callback_query(F.data == "a_resets")
async def cb_resets(cq: CallbackQuery):
    rows_db = q(
        "SELECT o.*, p.name pname, p.price pprice FROM orders o "
        "JOIN products p ON p.id=o.product_id "
        "WHERE p.name=? AND o.status IN ('new','paid') "
        "ORDER BY o.created_at DESC LIMIT 20", (RESET_PRODUCT_NAME,))
    if not rows_db:
        await show(cq, "Заявок на сброс HWID нет.", kb([b("⬅ Назад", "adm")]))
        return
    lines = ["<b>♻️ Заявки на сброс HWID</b>\n"]
    rows = []
    for o in rows_db:
        u = f"@{o['username']}" if o["username"] else f"id {o['user_id']}"
        status = "💰 ожидает проверки" if o["status"] == "paid" else "🕓 новый"
        lines.append(f"Заказ №{o['id']} · {esc(u)}\n{status} · {esc(o['pprice'])}")
        if o["status"] == "paid":
            rows.append([b(f"✅ Подтвердить №{o['id']}", f"ok:{o['id']}"),
                         b(f"❌ №{o['id']}", f"no:{o['id']}")])
    rows.append([b("⬅ Назад", "adm")])
    await show(cq, "\n\n".join(lines), kb(*rows))


# ---- ключи ----
@admin.callback_query(F.data == "a_keys")
async def cb_keys(cq: CallbackQuery):
    rows_db = q("SELECT * FROM keys ORDER BY created_at DESC LIMIT 15")
    text = "<b>Последние ключи</b>\n\n" + ("\n".join(
        f"<code>{r['key']}</code> - {key_status(r)}" for r in rows_db) or "пусто")
    text += ("\n\nУправление ключом: <code>/key КЛЮЧ</code>\n"
             "Добавить/отнять дни: <code>/adddays КЛЮЧ ДНИ</code>")
    await show(cq, text, kb([b("⬅ Назад", "adm")]))


def key_card(key):
    r = q("SELECT * FROM keys WHERE key=?", (key,), one=True)
    if not r:
        return "Ключ не найден.", None
    text = (f"<code>{r['key']}</code>\n{key_status(r)}\nСрок ключа: {r['days']} дн.\n"
            f"HWID: <code>{(r['hwid'] or '-')[:12]}</code>\nПокупатель: {r['buyer_id'] or '-'}\n"
            f"Сбросов: {r['resets']}")
    return text, kb([b("♻️ Сбросить HWID", f"kh:{key}"),
                     b("✅ Вернуть" if r["revoked"] else "⛔ Отозвать", f"kr:{key}")],
                    [b("+1 д", f"kx:{key}:1"), b("+7 д", f"kx:{key}:7"), b("+30 д", f"kx:{key}:30")],
                    [b("➕ Свои дни", f"kadd:{key}")])


@admin.message(Command("key"))
async def cmd_key(m: Message, command: CommandObject):
    text, markup = key_card((command.args or "").strip().upper())
    await m.answer(text, reply_markup=markup)


@admin.callback_query(F.data.startswith("kr:"))
async def cb_k_revoke(cq: CallbackQuery):
    k = cq.data[3:]
    ex("UPDATE keys SET revoked=1-revoked WHERE key=?", (k,))
    text, markup = key_card(k)
    await show(cq, text, markup)


@admin.callback_query(F.data.startswith("kh:"))
async def cb_k_hwid(cq: CallbackQuery):
    k = cq.data[3:]
    do_reset_hwid(k)
    text, markup = key_card(k)
    await show(cq, text, markup)


@admin.callback_query(F.data.startswith("kx:"))
async def cb_k_extend(cq: CallbackQuery):
    _, k, n = cq.data.split(":")
    r = q("SELECT * FROM keys WHERE key=?", (k,), one=True)
    if r:
        if r["expires_at"]:
            ex("UPDATE keys SET expires_at=expires_at+? WHERE key=?", (int(n) * 86400, k))
        else:
            ex("UPDATE keys SET days=days+? WHERE key=?", (int(n), k))
    text, markup = key_card(k)
    await show(cq, text, markup)


@admin.callback_query(F.data.startswith("kadd:"))
async def cb_k_adddays(cq: CallbackQuery, state: FSMContext):
    k = cq.data[5:]
    await state.set_state(AddDays.value)
    await state.update_data(key=k)
    await show(cq, f"Введи количество дней для ключа <code>{k}</code>.\n"
                   f"Можно отрицательное (например <code>-7</code>).\n/cancel - отмена")


@admin.message(AddDays.value)
async def msg_adddays(m: Message, state: FSMContext):
    d = await state.get_data()
    t = (m.text or "").strip()
    if not t.lstrip("-").isdigit():
        await m.answer("Нужно целое число дней.")
        return
    delta = int(t)
    key = d["key"]
    r = q("SELECT * FROM keys WHERE key=?", (key,), one=True)
    if not r:
        await state.clear()
        await m.answer("Ключ не найден.", reply_markup=admin_menu())
        return
    if r["expires_at"]:
        new_exp = max(int(time.time()), r["expires_at"] + delta * 86400)
        ex("UPDATE keys SET expires_at=? WHERE key=?", (new_exp, key))
    else:
        ex("UPDATE keys SET days=? WHERE key=?", (max(0, r["days"] + delta), key))
    await state.clear()
    text, markup = key_card(key)
    await m.answer(f"Готово. {delta:+d} дн.\n\n{text}", reply_markup=markup)
    if r["buyer_id"]:
        try:
            r2 = q("SELECT * FROM keys WHERE key=?", (key,), one=True)
            await m.bot.send_message(r["buyer_id"],
                                     f"🎁 Администратор изменил срок действия ключа <code>{key}</code> "
                                     f"на {delta:+d} дн.\n\n{key_status(r2)}")
        except Exception:
            pass


# ---- оплата / статистика ----
@admin.callback_query(F.data == "a_pay")
async def cb_pay(cq: CallbackQuery, state: FSMContext):
    await state.set_state(SetPayment.text)
    await show(cq, "Текущий текст оплаты:\n\n" + get_setting("payment_text", DEFAULT_PAYMENT) +
               "\n\nОтправь новый текст (можно HTML: <code>&lt;b&gt;</code>, <code>&lt;code&gt;</code>).\n/cancel - отмена")


@admin.message(SetPayment.text)
async def msg_pay(m: Message, state: FSMContext):
    set_setting("payment_text", m.html_text)
    await state.clear()
    await m.answer("Текст оплаты обновлён ✅", reply_markup=admin_menu())


@admin.callback_query(F.data == "a_stat")
async def cb_stat(cq: CallbackQuery):
    now = int(time.time())
    total = q("SELECT COUNT(*) n FROM keys", one=True)["n"]
    act = q("SELECT COUNT(*) n FROM keys WHERE hwid IS NOT NULL AND revoked=0 AND expires_at>?", (now,), one=True)["n"]
    free = q("SELECT COUNT(*) n FROM keys WHERE hwid IS NULL AND revoked=0", one=True)["n"]
    pend = q("SELECT COUNT(*) n FROM orders WHERE status='paid'", one=True)["n"]
    reset_pend = q("SELECT COUNT(*) n FROM orders o JOIN products p ON p.id=o.product_id "
                   "WHERE o.status='paid' AND p.name=?", (RESET_PRODUCT_NAME,), one=True)["n"]
    await show(cq, f"<b>Статистика</b>\n\nВсего ключей: {total}\nАктивных сейчас: {act}\n"
                   f"Не активировано: {free}\nЗаказов ждут проверки: {pend}\n"
                   f"Заявок на сброс HWID: {reset_pend}", kb([b("⬅ Назад", "adm")]))


# ============================ ЗАПУСК ============================
async def main():
    logging.basicConfig(level=logging.INFO)
    init_db()
    print("PUBLIC KEY (вставь в license_client.py -> PUBLIC_KEY_B64):\n" + PUB_B64 + "\n")

    app = web.Application()
    app.router.add_post("/auth", h_auth)
    app.router.add_get("/health", h_health)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, CFG["host"], int(CFG["port"])).start()
    print(f"Сервер лицензий: http://{CFG['host']}:{CFG['port']}/auth")

    bot = Bot(CFG["bot_token"], default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(admin)
    dp.include_router(user)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())