
platforms_dir=platforms
available_platforms_dir=platforms/available
default_list_filename=platforms/default.list.txt
list_filepath=platforms/list.txt
list_filename=list.txt

create_templates:
	@cp -nv $(default_list_filename) $(list_filepath)
	@mkdir -p $(available_platforms_dir)

install: create_templates
	cat $(list_filepath) | xargs echo | xargs -l bash -c 'git clone $$0 $(available_platforms_dir)/$$1'

update:
	@cd $(platforms_dir); \
		@cat $(list_filename) | xargs -I{} git clone {}
