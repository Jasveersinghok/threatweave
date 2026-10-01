.PHONY: ingest-attack run test eval lint typecheck check all

ingest-attack:
	python -m threatweave.knowledge.attack_ingest

run:
	streamlit run src/threatweave/app.py

test:
	pytest tests/ -v

eval:
	python eval/run_eval.py

lint:
	ruff check src/

typecheck:
	mypy src/ --ignore-missing-imports

check: lint typecheck test

all: ingest-attack check
