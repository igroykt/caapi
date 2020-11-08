# CAApi
Microsoft Certificate Authority библиотека для Python

# Зависимости
* Python 3.x
* OpenSSH

# Методы
* generate_config_for(user_fullname, user_dn, user_mail, user_domain) bool -> генерирует конфигурацию для запроса сертификата пользователя
* generate_cert_for(user_dn, cep_cert, cert_pass) bool -> генерирует сертификат пользователя