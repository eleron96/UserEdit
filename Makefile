run:
	poetry run python -m user_editor.app

make migrations:
	poetry run alembic revision --autogenerate -m "Added table"

db_upgrade:
	poetry run alembic upgrade head
db_downgrade:
	poetry run alembic downgrade -1

