# README for Selfrando Yocto layer
This is a Yocto layer file that adds Selfrando randomization support to any Yocto recipes that enable it.

## Instructions
To enable Selfrando for a recipe, perform the following steps:
* After checking out the Selfrando repository to a local path, add this layer to your `build/conf/bblayers.conf`:
```
BBLAYERS ?= " \
  .../poky/meta \
  .../poky/meta-poky \
  ... \
  /path/to/selfrando/Tools/Yocto/selfrando \
  "
```
* Add the following line to any recipe you wish to build with Selfrando:
```
inherit selfrandomize
```

Our layer includes an example `.bbappend` file for the `lighttpd` package that builds it using Selfrando support
(see the [lighttpd_%.bbappend](https://github.com/immunant/selfrando/blob/master/Tools/Yocto/selfrando/recipes-extended/lighttpd/lighttpd_%25.bbappend) file).

## More information
This layer was tested on the `rocko` release branch of the [poky](https://git.yoctoproject.org/cgit.cgi/poky) repository, and with a `qemuarm` machine.
Other Yocto releases and targets may work, but have not been tested.
