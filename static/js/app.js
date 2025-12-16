// Функция для переключения между формами входа и регистрации
function initAuthForms() {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const showRegister = document.getElementById('show-register');
    const backToLogin = document.getElementById('backToLogin');

    if (!loginForm || !registerForm || !showRegister || !backToLogin) {
        console.log('Элементы форм не найдены, страница не требует переключения форм');
        return;
    }

    // Показ формы регистрации
    showRegister.onclick = () => {
        loginForm.classList.add('hidden-element');
        registerForm.classList.remove('hidden-element');
        showRegister.classList.add('hidden-element');
    };

    // Возврат на форму входа
    backToLogin.onclick = () => {
        registerForm.classList.add('hidden-element');
        loginForm.classList.remove('hidden-element');
        showRegister.classList.remove('hidden-element');
    };
}

// Запуск при загрузке страницы
document.addEventListener('DOMContentLoaded', initAuthForms);