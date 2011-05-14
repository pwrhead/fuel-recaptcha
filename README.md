# ReCaptcha

ReCaptcha is a Fuel package that handles calling reCAPTCHA.

# Usage

To get captcha html:

	$captcha_html = ReCaptcha::instance()->get_html();

To validate user entry:

	if (ReCaptcha::instance()->check_answer(Input::real_ip(), Input::post('recaptcha_challenge_field'), Input::post('recaptcha_response_field')))
	{
		// valid
	}
	else
	{
		// invalid
	}