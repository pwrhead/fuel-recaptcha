<?php

/**
* ReCaptcha Helper for FuelPHP
*
* @package ReCaptcha
* @version 1.0
*/

Autoloader::add_core_namespace('ReCaptcha');

Autoloader::add_classes(array(
'ReCaptcha\\ReCaptcha' => __DIR__.'/classes/recaptcha.php'
));
