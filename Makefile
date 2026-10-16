.PHONY: setup test eval demo ui
setup:
	pip install -r requirements.txt
test:
	pytest -q
eval:
	python -m sphilter.evaluate
demo:
	python -m sphilter.demo A1
ui:
	streamlit run app.py
