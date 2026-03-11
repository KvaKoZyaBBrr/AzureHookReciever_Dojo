# Описание

Web приложение, обрабатывающее входящие Post-запросы и отправляющее запрос в Api DefectDojo.

# Принцип работы

Приложение является Web-приложением. Для работы доступен Endpoint /api/. 
Необходимо использовать совсместно с WebHook для AzureDevOps. Основные требования:
- Тип события: Изменение состояния WorkItem
- Тип WorkItem: Vulnerability - кастомный WI, содержащий параметры:
  - System.WorkItemType: "Vulnerability"
  - System.State: ["New", "Active", "Resolved", "Closed", "False Positive", "Ignored"]
  - Custom.Deduplication: "<идентификаторы уязвимости в DefectDojo, разделенные символом ';'>". Может содержать html-теги (Пример: "\<div>\<span style=\"display:inline !important;\">1496; 1497\</span>\<br> \</div>" или "1496; 1497")

Конфигурация определена в appsettings.json (appsettings.Development.json):

```JSON
{
  "App": {
    "Dojo":{
      "ApiUrl": "http://192.168.80.20:48080/api/",
      "Authorization": "Token 4b5d0386d26d172e77961f6762dd2290a3902684"
    }
  }
}
```

При получении запроса, производятся следующие действия:
1. Чтение запроса. Выделение следующего пути: "resource"."revision"."fields". Здесь находится вся информация по WorkItem
2. Проверка свойства System.WorkItemType. Если не "Vulnerability" - возврат false
3. Чтение свойства System.State и установка флагов для dojo (по умолчанию - все false):
    - New -> active = "true"
    - Active -> under_review = "true"; active = "true"
    - Resolved -> verified = "true"; active = "true"
    - Closed -> is_mitigated = "true"
    - False Positive -> false_p = "true"
    - Ignored -> out_of_scope = "true"
    - В ином случае - ошибка.
4. Чтение(и чистка) свойства Custom.Deduplication и получение списка индетификаторов уязвимостей. В случае отсутствия результата - ошибка.
5. Для каждой уязвимости из п.4 посылается Patch-запрос в \<App:Dojo:ApiUrl>v2/findings/\<id>/ с содержимым, полученным в п.2. Токен для запроса в \<App:Dojo:Authorization>.
6. Возврат true
