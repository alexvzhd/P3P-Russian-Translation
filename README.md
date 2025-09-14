# Порт перевода [группы "Котонэ"](https://vk.com/kotone_team)
# для MS Store/Game Pass/Xbox App 
# версии Persona 3 Portable

## Предварительные условия
Игра должна быть установлена в папку доступную для изменения файлов.

Как изменить место установки игр в приложении Xbox на Windows 11:

📌 Шаг 1: Открой приложение Xbox
- Нажми `Пуск` → найди `Xbox` и открой приложение.

⚙️ Шаг 2: Перейди в настройки
- В левом верхнем углу нажми на иконку профиля.
- Выбери Настройки.

📂 Шаг 3: Измени путь установки
- Перейди в раздел Параметры установки.
- Найди "Изменить место, где это приложение устанавливает игры по умолчанию".
- Выбери нужный диск из выпадающего списка.
- Далее нажми кнопку "Изменить папку" и выбери нужную папку для установки (Например: C:\Games\)

Должно получится так:
<img width="920" height="612" alt="image" src="https://github.com/user-attachments/assets/73a18d64-b266-42f9-8b42-7301a693d2c5" />



## Устанавливаем русификатор от [группы "Котонэ"](https://vk.com/kotone_team)
1. Скачиваем загрузчик модов [Reloaded II](https://github.com/Reloaded-Project/Reloaded-II/releases/latest)
2. Распаковываем скачанный по ссылке выше Release.zip (например в C:\Games\Reloaded) и запускаем Reloaded-II.exe
3. При первом запуске Reloaded может попросить установить или обновить необходимые для его работы компоненты (Например .NET 9.0 Desktop Runtime и т.п.)
4. Жмём на кнопку плюса в кружке, открываем папку с играми Xbox → Persona 3 Portable → Content → выбираем p3p_sln_DT_m.exe (Например: C:\Games\Persona 3 Portable\Content\p3p_sln_DT_m.exe)
<img width="1050" height="630" alt="image" src="https://github.com/user-attachments/assets/1dc88bc5-e084-47ea-a174-bf7ceb9e2d8b" />

5. Игра добавится в список игр над кнопкой которую только что нажимали (игра уже добавлена на скриншоте выше).
6. Далее переходим на страницу перевода от группы "Котонэ" на сайте https://gamebanana.com/mods/599324  
7. В центре страницы жмём на кнопку "Reloaded II 1-Click Install"
<img width="419" height="153" alt="image" src="https://github.com/user-attachments/assets/7a7e18b8-c09a-496e-b649-22003641a50d" />

8. Установится мод с переводом и все зависимости. Зависимости будут видны в списке, но самого перевода видно не будет, это предстоит исправить.
9. Закрывыем программу Reloaded II, она нам пока не понадобится

## Изменяем русификатор чтобы он работал с MS Store/Game Pass/Xbox App версией Persona 3 Portable
1. Переходим в папку куда распаковали Release.zip (Например: в C:\Games\Reloaded)
2. Далее переходим в Mods → p3ppc.text.russianTranslation (Например: C:\Games\Reloaded\Mods\p3ppc.text.russianTranslation)
3. Находим файл ModConfig.json и открываем его в блокноте
4. Ищем строку SupportedAppId, добавляем строкой ниже название нашего exe файла двойных кавычках "p3p_sln_dt_m.exe"
5. Должно получиться так:
```
  "SupportedAppId": [
    "p3p_sln_dt_m.exe",
    "p3p.exe"
  ],
```
5. Качаем файлы EmbededFiles.json, EmbededFilesRawReplace.json и Pointermap.json с этой страницы и копируем их с заменой в папку p3ppc.text.russianTranslation (Например: C:\Games\Reloaded\Mods\p3ppc.text.russianTranslation)
6. Снова запускаем Reloaded-II.exe и в списке модов теперь видим перевод, отмечаем кликаем по квадратику слева от названия чтобы там появился плюсик
<img width="1350" height="855" alt="image" src="https://github.com/user-attachments/assets/f710ff31-fe2f-4880-8c7c-9eb809b6100d" />

7. Перевод установлен, можно закрывать Reloaded II и запускать игру как обычно из меню Пуск/из приложения Xbox и т.д.
8. При запуске игры будет появляться окно консоли с пробегающими строчками перевода, это норма, без этого окна перевод не будет работать так как текст заменяется в процессе запуска.

-- Русификатор Persona 3 Portable для версии из Microsoft Store / Game Pass / приложения Xbox --

