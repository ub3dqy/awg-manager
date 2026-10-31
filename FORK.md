# AWG Manager — открытая разработка ub3dqy

Исходный проект: [hoaxisr/awg-manager](https://github.com/hoaxisr/awg-manager).
Форк: [ub3dqy/awg-manager](https://github.com/ub3dqy/awg-manager).
Развитие форка: Dima Mak / ub3dqy.

## Лицензия и связь с автором

Код форка и собственные дополнения распространяются под MIT, как исходный
AWG Manager. Оригинальная лицензия и указание авторства сохраняются. У сторонних
компонентов остаются их собственные лицензии и уведомления.

Форк развивается самостоятельно. Готовые изменения можно предложить исходному
проекту; решение об их включении остаётся за его автором. Обновления исходного
проекта переносим после проверки совместимости с нашими изменениями.

## Разработка

- `develop` — общая основа разработки; изменение функций проходит отдельной веткой
  и проверкой перед объединением.
- Для каждого изменения описываем назначение, ограничения и результаты проверок.
- Данные роутеров, ключи, пароли, личные журналы и адреса пользователей в репозиторий
  не включаются. Для примеров используются демонстрационные данные.
- Изменение настроек и установка на рабочие роутеры не выполняются автоматически.

Первая собственная функция разрабатывается в ветке
[`feat/service-connectivity-diagnostics`](https://github.com/ub3dqy/awg-manager/tree/feat/service-connectivity-diagnostics):
диагностика конкретного устройства и сервиса —
политика доступа, DNS, совпадения в списках маршрутизации, наблюдаемые соединения
и необязательная TCP-проверка через выбранный интерфейс. Описание —
[SERVICE_DIAGNOSTICS.md](https://github.com/ub3dqy/awg-manager/blob/feat/service-connectivity-diagnostics/SERVICE_DIAGNOSTICS.md).

## Сборки и обновления

Отдельных установочных выпусков форка пока нет. Команды установки и инфраструктура
обновлений в исходной документации относятся к проекту hoaxisr. Их нельзя считать
каналом установки нашей версии.

До первого выпуска нужно отдельно проверить сборку для поддерживаемых роутеров,
обновление и возврат к предыдущей версии, указать собственный источник обновлений
и проверить работу на устройстве. Экспериментальная ветка не объявляется готовым
выпуском только по результату локальных тестов.

## English

This public fork is maintained by Dima Mak / ub3dqy and retains the original
project's MIT license and attribution. Fork contributions use MIT as well;
third-party components retain their respective licenses. Features are developed
and reviewed in separate branches. Compatible changes may be offered upstream.
No installable fork release is available yet. Original installation commands
and update infrastructure still refer to hoaxisr's project.
