"""WSGI entry: licence service + read-only dashboard.

gunicorn wsgi:application --bind 0.0.0.0:$PORT --workers 1 --threads 4
"""
from licence_service.app import application as licence_app
from dashboard_api import application as dashboard_app


def application(environ, start_response):
    path = environ.get("PATH_INFO") or ""
    if path.startswith("/dashboard") or path.startswith("/api/dashboard"):
        return dashboard_app(environ, start_response)
    return licence_app(environ, start_response)
