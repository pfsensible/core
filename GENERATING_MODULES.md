# Generating Modules with pfsensible-generate-module

The process of writing basic pfsensible modules is hopefully greatly simplified by using
the pfsensible-generate-module script. The basic workflow is as follows:

* Navigate in the pfSense web interface to the area you want to write a module for. This should be a page where you can edit
settings or one where you are adding an item.
* Copy the URL of the page - you will pass it to the `--url` option of the script.

## Modules that manage multiple items

If this is a module that will allow you to create multiple items (e.g. aliases, rules):
* Save a minimal item with a name (often Name or Description) of `item_min` (or something else if that does not work).
Simply try immediately saving an item with just that name, then fill out fields one at a time and re-save until pfSense
stops complaining about missing items.
* Save a "fully" configured item with a name of `item_full` (or something else if that will not work). It may be
helpful to change as many options away from the default as possible. Focus on settings that would be useful to you.
* Run the script:

      misc/pfsensible-generate-module --url URL

if you needed to use different names for the items than `item_min` and `item_full` you can set them with the `--item-min` and
`--item-full` options.

## Modules that configure something

If this is a module that will just configure something, it is best to start with the default configuration.  Then add the
--is-config` option:

    misc/pfsensible-generate-module --url URL --is-config

## Other options

* Pass the `--author-name`, `--author-email`, and `--author-handle` options to give yourself credit!
* You will need to add the `--user` and/or `--password` options if you have changed from the install defaults.
* If the automatically determined module name does not seem correct, you can change it with the `--module-name` option.
* It may make sense to create a module for different types of items if the parameters are wildly different (as is the case
with the different types of authentication servers for example). If so, add the `--type-suffix` option to add the "type"
of the item as a suffix to the module name.

## Final steps

Review the items in the generated module flagged with `TODO` for possible changes needed.
