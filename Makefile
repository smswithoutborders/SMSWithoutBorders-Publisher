
python=python3

venv_path=venv
platforms_dir=platforms
available_platforms_dir=platforms/available
default_list_filename=platforms/default.list.txt
list_filepath=platforms/list.txt
list_filename=list.txt

pip=pip3

create_templates:
	@cp -nv $(default_list_filename) $(list_filepath)
	@mkdir -p $(available_platforms_dir)

install: create_templates
	@$(python) -m venv $(venv_path)
	@( \
		. $(venv_path)/bin/activate; \
		$(pip) install -r requirements.txt; \
		cat $(list_filepath) | xargs echo | xargs -l bash -c 'git clone $$0 $(available_platforms_dir)/$$1; make -C $(available_platforms_dir)/$$1' \
	)
	@echo "[*] python requirements installation completed successfully"

update:
	@$(python) -m venv $(venv_path)
	@( \
		cat $(list_filepath) | xargs echo | xargs -l bash -c 'git clone $$0 $(available_platforms_dir)/$$1 && make -C $(available_platforms_dir)/$$1'
		. $(venv_path)/bin/activate; \
		$(pip) install -r requirements.txt \
	)


remove:
	@rm -rfv $(available_platforms_dir)/*
