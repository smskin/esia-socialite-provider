## Модуль интеграции с ЕСИА (ГосУслуги) для Laravel Socialite

Документация ЕСИА: https://digital.gov.ru/ru/documents/6186/

## Получение доступа к контуру ЕСИА
Для получения доступа к контуру ЕСИА нужно:
- Получить КЭП на руководителя организации
- Получить экспортируемую КЭП на ответственного сотрудника организации (именно она будет загружена на сервер и будет использоваться для подписания запросов)
- Подготовить окружение на основном портале ГосУслуг
    - Зарегистрировать организацию
    - Добавить в организацию доверенного сотрудника и предоставить ему права на работу с технологическим порталом
    - Зарегистрировать информационную систему (https://partners.gosuslugi.ru/systems/add)
    - Добавить в конфигурацию информационной системы КЭП ответственного сотрудника
- Подготовить окружение тестового портала ГосУслуг (https://esia-portal1.test.gosuslugi.ru)
    - Зарегистрировать профили руководителя и ответственного сотрудника
    - Зарегистрировать организацию в профиле руководителя
    - Добавить в организацию доверенного сотрудника и предоставить ему права на работу с технологическим порталом
    - Зарегистрировать информационную систему (https://esia-portal1.test.gosuslugi.ru/console/tech)
    - Добавить в конфигурацию информационной системы КЭП ответственного сотрудника
- Подготовить заявление на присоединение в соответствии с документом https://digital.gov.ru/ru/documents/4244/ и отправить заявление на электронную почту
- Дождаться ответа с разрешением на присоединение (2-4 недели)
- Выгрузить ЭЦП ответственного сотрудника для дальнейшего использования его на сервере (https://smskin.github.io/export-gost-certificate/index.html)

### Конфигурация
В config/services.php необходимо добавить следующий блок:

    'esia' => [  
	    'client_id' => env('ESIA_CLIENT_ID'),  
	    'client_secret' => '',  
	    'portal_url' => env('ESIA_PORTAL_URL', 'https://esia-portal1.test.gosuslugi.ru'),  
	    'redirect' => env('ESIA_REDIRECT_URL'),  
	    'public_key_path' => env('ESIA_PUBLIC_KEY_PATH'),
	    'public_key' => env('ESIA_PUBLIC_KEY'), 
	    'private_key_path' => env('ESIA_PRIVATE_KEY_PATH'),
	    'private_key' => env('ESIA_PRIVATE_KEY'),
	    'private_key_password' => env('ESIA_PRIVATE_KEY_PASSWORD')
	 ]
- client_id - идентификатор приложения (термин ЕСИА "Мнемоника")
- client_secret - оставляем пустым. Его наличие требует SocialiteProvider, но он не используется поскольку ЕСИА требует подписание запросов ЭЦП
- portal_url - URL портала ЕСИА
- redirect - редирект URL для возврата
- public_key - публичный ключ КЭП
- public_key_path - путь до публичного ключа КЭП (используется, когда не объявлен public_key)
- private_key - закрытый ключ КЭП
- private_key_path - путь до закрытого ключа КЭП (используется, когда не объявлен private_key)
- private_key_password - пароль контейнера закрытого ключа КЭП