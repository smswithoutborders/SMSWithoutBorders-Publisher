
python=python3

venv_path=venv
platforms_dir=platforms
available_platforms_dir=platforms/available
default_list_filename=platforms/default.list.txt
list_filepath=platforms/list.txt
list_filename=list.txt

pip=pip3

# cat $(list_filepath) | xargs -l echo $$0 | xargs -l bash -c '[ ! -d $(available_platforms_dir)/$$1 ] &&  ( git clone $$0 $(available_platforms_dir)/$$1 && make -C $(available_platforms_dir)/$$1 )' \

create_templates:
	@cp -nv $(default_list_filename) $(list_filepath)
	@mkdir -p $(available_platforms_dir)

install: create_templates
	@$(python) -m venv $(venv_path)
	@( \
		. $(venv_path)/bin/activate; \
		$(pip) install -r requirements.txt; \
		git clone https://github.com/smswithoutborders/SMSwithoutBorders-customplatform-Gmail.git $(available_platforms_dir)/gmail && \
		$(pip) install -r $(available_platforms_dir)/gmail/requirements.txt; \
		git clone https://github.com/smswithoutborders/SMSwithoutBorders-customplatform-Twitter.git $(available_platforms_dir)/twitter && \
		$(pip) install -r $(available_platforms_dir)/twitter/requirements.txt; \
	)
	@echo "[*] python requirements installation completed successfully"

