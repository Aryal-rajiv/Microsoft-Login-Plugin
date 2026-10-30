/**
 * Moves the "Sign in with Microsoft" button to the top of the login form.
 * Without JavaScript the button simply stays where the login_form hook prints it.
 */
( function () {
	var block = document.querySelector( '#loginform .msentra-sso' );
	var form = document.getElementById( 'loginform' );

	if ( block && form && form.firstElementChild !== block ) {
		form.insertBefore( block, form.firstElementChild );
		block.classList.add( 'msentra-sso--top' );
	}
}() );
