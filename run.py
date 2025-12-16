from app import app
import werkzeug.serving

# Кастомный обработчик для исключения передачи информации о версии сервера
class NoServerHeaderRequestHandler(werkzeug.serving.WSGIRequestHandler):

    def send_response(self, *args, **kwargs):
        # Делегирование базовой функциональности отправки ответа
        super().send_response(*args, **kwargs)

    def version_string(self):
        # Возвращение пустой строки вместо информации о версии сервера
        return ""

    def send_header(self, keyword, value):
        # Игнорирование заголовка Server для предотвращения раскрытия информации
        if keyword.lower() == 'server':
            return
        super().send_header(keyword, value)

if __name__ == '__main__':
    # Запуск приложения с использованием кастомного обработчика безопасности
    werkzeug.serving.run_simple(
        '0.0.0.0',
        5000,
        app,
        threaded=True,
        request_handler=NoServerHeaderRequestHandler
    )









