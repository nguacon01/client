#!/bin/bash
exec gunicorn --config gunicorn_config.py --bind unix:client.sock -m 007 wsgi:app