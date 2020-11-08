# CAApi
Microsoft Certificate Authority библиотека для Python

# Зависимости
* Python 3.x
* OpenSSH
* OpenSSL

# Настройка пользователя
Логинимся на Windows сервер под пользователем с правами администратора домена (он же будет использоваться для ssh). Запускаем certmgr.msc и выполняем "Запросить новый сертификат -> Политика регистрации Active Directory -> Агент регистрации". Запускаем оснастку "Центр сертификации" и выполняем "Создать -> Выдаваемый шаблон сертификата" и добавляем шаблоны "Компьютер" и "Агент регистрации".

# Настройка шаблона
В оснастке "Центр сертификации" выполняем "Шаблоны сертификации -> Управление". Создаем копию шаблона "Агент регистрации". Далее по скриншотам:

![Общие](https://github.com/igroykt/caapi/blob/master/assets/template_obshie.png?raw=true)

![Совместимость](https://github.com/igroykt/caapi/blob/master/assets/template_sovmestimost.png?raw=true)

![Безопасность](https://github.com/igroykt/caapi/blob/master/assets/template_bezopasnost.png?raw=true)

![Обработка](https://github.com/igroykt/caapi/blob/master/assets/template_obrabotka.png?raw=true)

![Шифрование](https://github.com/igroykt/caapi/blob/master/assets/template_shifrovanie.png?raw=true)

![Субъект](https://github.com/igroykt/caapi/blob/master/assets/template_subject.png?raw=true)

![Выдача](https://github.com/igroykt/caapi/blob/master/assets/template_vidacha.png?raw=true)

В остальных вкладках все оставляем по-умолчанию.

# Настройка SSH
Говорят сейчас Windows Server по-умолчанию идет с ssh. Но если у вас обновленный сервер, то он вряд ли есть. Я ставил с репозитория [chocolatey](https://chocolatey.org). Генерируем ключ на Linux сервере:
```bash
ssh-keygen -t rsa
cat /path/to/id_rsa.pub
```
Открытый ключ прописываем на Windows Server по пути %programdata%\ssh\administrators_authorized_keys. Проверяем подключение:
```bash
ssh administrator@winserv_ip 'whoami'
```

# Методы
* generate_config(user_fullname, user_dn, user_mail, user_domain) bool -> генерирует конфигурацию для запроса сертификата пользователя
* generate_cert(user_dn, cert_pass, cep_cert) bool -> генерирует сертификат пользователя
* revoke_cert(user_dn, cert_pass, reason) bool -> отзывает сертификат пользователя

# Коды отзывов
| Код | Причина                                                                                                                                         |
|-----|-------------------------------------------------------------------------------------------------------------------------------------------------|
| 0   | Не указано (по-умолчанию). Не рекомендуется использовать из-за сложностей в будущем при аудите.                                                 |
| 1   | Ключ сертификата скомпромитирован. Следует использовать при утечке ключей сертификатов или их паролей.                                          |
| 2   | Центр сертификации скомпрометирован. Следует использовать, если центр сертификации был взломан.                                                 |
| 3   | Изменение принадлежности. Следует использовать, если пользователь был уволен.                                                                   |
| 4   | Заменено. Используется, если пользователь забыл пароль, сломал смарт-карту или изменил имя.                                                     |
| 5   | Прекращение работы. Используется для отзыва сертификата ЦС, когда ЦС прекращает свою работу и больше не будет использоваться.                   |
| 6   | Временный отзыв. Это значит, что ЦС не будет распозновать сертификат на время отзыва. Сертификат может быть возвращен к использованию (кодом 8).|
| 8   | Удаление из списка отзыва. Возврат сертификата к использованию при этом сертификат все еще будет в списке отозованных, но с кодом 8.            |