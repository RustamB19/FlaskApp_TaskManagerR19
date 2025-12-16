// navigation.js - для навигационных кнопок на всех страницах
function initNavigation() {
    console.log('Инициализация навигационных кнопок...');

    // Ищем ВСЕ кнопки с атрибутом data-href (а не только с классом .js-navigate)
    const navButtons = document.querySelectorAll('button[data-href]');

    if (navButtons.length === 0) {
        console.log('Навигационные кнопки не найдены');
        return;
    }

    console.log(`Найдено ${navButtons.length} навигационных кнопок`);

    // Добавляем обработчик клика для каждой кнопки
    navButtons.forEach(button => {
        button.addEventListener('click', function() {
            const url = this.getAttribute('data-href');
            if (url) {
                console.log(`Переход по ссылке: ${url}`);
                window.location.href = url;
            }
        });
    });

    console.log('Навигационные кнопки инициализированы');
}

// Запуск при загрузке страницы
document.addEventListener('DOMContentLoaded', initNavigation);