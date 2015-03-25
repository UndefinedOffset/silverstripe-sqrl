SilverStripe SQRL Authenticator
=================
SilverStripe implementation of [GRC's SQRL authentication](https://www.grc.com/sqrl/sqrl.htm) system, at this time this module is very experimental and has allot of work yet to go. For more information on SQRL see [here](https://www.grc.com/sqrl/sqrl.htm) and [here](http://sqrl.pl/guide/).

## Requirements
* SilverStripe 3.1+

## Installation
* Download the module from here https://github.com/UndefinedOffset/silverstripe-sqrl/archive/master.zip
* Extract the downloaded archive into your site root so that the destination folder is called sqrl, opening the extracted folder should contain _config.php in the root along with other files/folders
* Run dev/build?flush=all to regenerate the manifest

If you prefer you may also install using composer:
```
composer require undefinedoffset/silverstripe-sqrl
```
