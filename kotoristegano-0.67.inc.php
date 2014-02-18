<?php

/**
 * KotoriStegano PHP Class
 *
 * Quick and dirty image steganography class
 * using LSB encoding, optional gz-compression
 * and AES-256 encryption
 *
 * Requires gd2, mcrypt, mhash, zlib libraries
 *
 * More documentation (German language):
 * http://www.kotori.de/wissen/daten-in-bildern-verstecken-steganographie.html
 *
 * The use of steganography and cryptography is legal by German law, though the situation in
 * other countries might be different. Please inform yourself about your local laws and
 * regulations before any use and implementation of this class. kotori web solutions Maren Arnhold
 * will not assume any responsibility or liability for any consequences for you or other persons 
 * which may arise from the use of this class. With the download and application of this code, you
 * are expressly accepting the terms and conditions above.
 *
 * Die Verwendung von Steganographie und Kryptographie ist nach deutscher Gesetzgebung legal, was aber nicht 
 * für alle Staaten gleichermaßen zutreffen muss. Informieren Sie sich vor dem Einsatz der hier geschilderten 
 * Kenntnisse bitte über Ihre lokale Rechtslage. kotori web solutions Maren Arnhold übernimmt in keiner Form die 
 * Haftung oder Verantwortung für Folgen jedweder Art, die Ihnen oder anderen Personen durch die 
 * Verwendung dieser Steganographieklasse entstehen. Mit Download und Anwendung des Codes erklären Sie sich 
 * mit diesen Bedingungen ausdrücklich als einverstanden.
 *
 * @author     Maren Arnhold <maren@kotori.de>
 * @copyright  (c) 2012 kotori web solutions Maren Arnhold, Berlin, Germany - http://www.kotori.de
 * @license    http://opensource.org/licenses/osl-3.0.php  Open Software License 3.0
 * @version    v0.67 - 19-Oct-2012
 */

class KotoriStegano {

	/* Protected class variables */

	protected $img_size_width;
	protected $img_size_height;
	protected $img_data;

	/* Methods */

	protected function loadJpg($imgname) {

		/* Import image from JPG */ 

		$img = @ImageCreateFromJPEG ($imgname); 

	    if (!$img) { die ("Error opening ".$imgname.". Exiting."); };

		$this->img_size_width = imagesx($img);
		$this->img_size_height = imagesy($img);
		$this->img_data = $img;

	}


	protected function loadPng($imgname) {

		/* Import image from PNG */ 

		$img = @ImageCreateFromPNG ($imgname);

		if (!$img) { die ("Error opening ".$imgname.". Exiting."); };

		$this->img_size_width = imagesx($img);
		$this->img_size_height = imagesy($img);
		$this->img_data = $img;

	}


	protected function exportPng() {

		/* Export image to PNG */

		$img = $this->img_data;

		header('Content-Type: image/png');
		imagepng($img);
		imagedestroy($img);


	}


	protected function makeEvenPixels() {

		/* Set all color values per channel and pixel to the next smaller, even number */

		$img = $this->img_data;

		for($y=0;$y<($this->img_size_height);$y++){


			for($x=0;$x<($this->img_size_width);$x++){


				$img_original_color = imagecolorat($img,$x,$y);
				$r = ($img_original_color >> 16) & 0xFF;
				$g = ($img_original_color >> 8) & 0xFF;
				$b = $img_original_color & 0xFF;

				if (($r % 2) == 1) {	

					$r--;

				};

				if (($g % 2) == 1) {	

					$g--;

				};

				if (($b % 2) == 1) {	

					$b--;

				};

				$img_modified_color = imagecolorallocate($img, $r, $g, $b);
				imagesetpixel($img, $x, $y, $img_modified_color);

			}

		}

		$this->img_data = $img;

	}

	
	protected function hideText($msg,$visualize,$compress,$encrypt,$passphrase,$vertical) {

		/* Hide text in picture */
		$img = $this->img_data;

		/* Encrypt string with AES-256 and passphrase SHA256 hash, if applicable */
		if ($encrypt == 1) { 
		
			$encrypt_key = mhash(MHASH_SHA256,$passphrase); 
			$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
			$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
			$msg = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $encrypt_key, $msg, MCRYPT_MODE_ECB, $iv);
						
		};
		
		/* Compress string if appropriate flag is set. */
		if ($compress == 1) { $msg = gzdeflate($msg,9);	};
		
		/* Is it possible to fit the ciphertext into this image? If not, stop here. */
		$pixel_sum = ($this->img_size_width)*($this->img_size_height);

		/* Three channels per pixel. */
		$pixel_sum = $pixel_sum * 3;

		/* 8 bit per character. */
		$text_length_binary = strlen($msg)*8;

		/* Exit if image is too small */
		if ( $pixel_sum < $text_length_binary ) { die ("Image too small for ciphertext. Exiting."); } 
		
		/* Equalize pic */
		$this->makeEvenPixels();
		$msgcounter = 0;
		$msg_bin = "";

		/* Go through ciphertext, converting each char to its binary value */
		while (isset($msg[$msgcounter])){

			$binary_value = decbin(ord($msg[$msgcounter]));

			/* Preserve leading zeroes */

			$binary_value = substr("00000000",0,8 - strlen($binary_value)) . $binary_value;

			$msg_bin .= $binary_value;

			$msgcounter++;

		}

		$msgcounter = 0;

		if ($vertical == 0) { 
		
			$axis_1 = $this->img_size_height;
			$axis_2 = $this->img_size_width;

		} else { 
		
			$axis_1 = $this->img_size_width;
			$axis_2 = $this->img_size_height;
		
		};
		
		for($y=0;$y<$axis_1;$y++){
		
			for($x=0;$x<$axis_2;$x++){


				if ($visualize != 1) {

					/* Standard mode. Don't visualize encoding. */

					if ($vertical == 0) { $img_original_color = imagecolorat($img,$x,$y); };
					if ($vertical == 1) { $img_original_color = imagecolorat($img,$y,$x); };
					
					$r = ($img_original_color >> 16) & 0xFF;
					$g = ($img_original_color >> 8) & 0xFF;
					$b = $img_original_color & 0xFF;

					/* Increment this pixel's red byte by the current value from the binary string - 0 rsp. 1. */
					if (isset($msg_bin[$msgcounter])) { $r += $msg_bin[$msgcounter]; };

					/* Advance to next binary digit */
					$msgcounter++;

					/* Increment this pixel's green byte by the current value from the binary string - 0 rsp. 1. */
					if (isset($msg_bin[$msgcounter])) { $g += $msg_bin[$msgcounter]; };

					/* Advance to next binary digit */
					$msgcounter++;

					/* Increment this pixel's blue byte by the current value from the binary string - 0 rsp. 1. */
					if (isset($msg_bin[$msgcounter])) { $b += $msg_bin[$msgcounter]; };
				
					/* Advance to next binary digit */
					$msgcounter++;

					/* Modify pixel now */
					$img_modified_color = imagecolorallocate($img, $r, $g, $b);								
					if ($vertical == 0) { imagesetpixel($img, $x, $y, $img_modified_color); };
					if ($vertical == 1) { imagesetpixel($img, $y, $x, $img_modified_color); };
				
				} else {

					/* Do visualize encoding for diagnostic and demonstrative purposes */
				
					if ($vertical == 0) { $img_original_color = imagecolorat($img,$x,$y); };
					if ($vertical == 1) { $img_original_color = imagecolorat($img,$y,$x); };

					$r = ($img_original_color >> 16) & 0xFF;
					$g = ($img_original_color >> 8) & 0xFF;
					$b = $img_original_color & 0xFF;

					/* Set pixel's red byte to &#FF if binary digit is 1, else set to &#00. */
					if (isset($msg_bin[$msgcounter])) { if ($msg_bin[$msgcounter] == "1") { $r = 255; } else { $r = 0; };  };

					/* Advance to next binary digit */
					$msgcounter++;

					/* Set pixel's green byte to &#FF if binary digit is 1, else set to &#00. */
					if (isset($msg_bin[$msgcounter])) { if ($msg_bin[$msgcounter] == "1") { $g = 255; } else { $g = 0; };  };

					/* Advance to next binary digit */
					$msgcounter++;

					/* Set pixel's blue byte to &#FF if binary digit is 1, else set to &#00. */
					if (isset($msg_bin[$msgcounter])) { if ($msg_bin[$msgcounter] == "1") { $b = 255; } else { $b = 0; };  };
				
					/* Advance to next binary digit */
					$msgcounter++;

					/* Modify pixel now */
					$img_modified_color = imagecolorallocate($img, $r, $g, $b);
					if ($vertical == 0) { imagesetpixel($img, $x, $y, $img_modified_color); };
					if ($vertical == 1) { imagesetpixel($img, $y, $x, $img_modified_color); };

				}

			}

		}

		$this->img_data = $img;

	}

	
	protected function extractText($compress,$decrypt,$passphrase,$vertical){

		/* Extract text from picture */

		$img = $this->img_data;

		$decoded_text_ascii = "";
		$decoded_text_bin = "";

		if ($vertical == 0) { 
		
			$axis_1 = $this->img_size_height;
			$axis_2 = $this->img_size_width;

		} else { 
		
			$axis_1 = $this->img_size_width;
			$axis_2 = $this->img_size_height;
		
		};
		
		for($y=0;$y<$axis_1;$y++){

			for($x=0;$x<$axis_2;$x++){

				if ($vertical == 0) { $img_original_color = imagecolorat($img,$x,$y); };
				if ($vertical == 1) { $img_original_color = imagecolorat($img,$y,$x); };
				$r = ($img_original_color >> 16) & 0xFF;
				$g = ($img_original_color >> 8) & 0xFF;
				$b = $img_original_color & 0xFF;

				$decoded_text_bin .= ($r % 2);
				$decoded_text_bin .= ($g % 2);
				$decoded_text_bin .= ($b % 2);

			}

		}

		$decoded_text_ascii_array = str_split ( $decoded_text_bin, 8 );

		foreach ($decoded_text_ascii_array as $da) {

			$decoded_text_ascii .= chr(bindec($da));

		}


		/* If compressed flag is set, decompress message */
		if ($compress == 1){ $decoded_text_ascii = gzinflate($decoded_text_ascii); };
				
		/* If decrypt flag is set, decrypt message */
		if ($decrypt == 1){ 

			$encrypt_key = mhash(MHASH_SHA256,$passphrase); 
			$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
			$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
			$decoded_text_ascii = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $encrypt_key, $decoded_text_ascii, MCRYPT_MODE_ECB, $iv);

		};

		return $decoded_text_ascii;

	}

	
	protected function loadText($txtname) {
	
		/* Import ciphertext from file */
	
		return file_get_contents($txtname);
	
	}
	
	
	public function encode($txtname,$imagename,$visualize = 0,$compress = 0,$encrypt = 0,$passphrase = "",$vertical = 0) {

		/* Default encode function */
		/*
			Parameters:
			
			$txtname		string					Filename (incl. path) of input text
			$imagename		string					Filename (incl. path) of input image
			$visualize		0=false (default), 1=true		Diagnostic mode
			$compress		0=false (default), 1=true		Compress input text
			$encrypt		0=false (default), 1=true		AES-256 encryption
			$passphrase		string					Encryption key
			$vertical		0=false (default), 1=true		If true, encode steganogram from top to bottom, left to right (columnwise).
											If false, encode steganogram from left to right, top to bottom (linewise).		
		*/

		$imgdata = getimagesize($imagename);
		$imgtype = $imgdata['mime'];
		$ciphertext = $this->loadText($txtname);
		
		/* Load proper import function according to mimetype */
		switch ($imgtype) {

			case "image/jpeg": $this->loadJpg($imagename); break;

			case "image/png": $this->loadPng($imagename);  break;

			default: die ("No suitable input image. Exiting."); break;

		};

		$this->hideText($ciphertext,$visualize,$compress,$encrypt,$passphrase,$vertical);
		$this->exportPng($this->img_data);

	}


	public function decode($imagename,$verbose=0,$compress=0,$decrypt=0,$passphrase="",$vertical=0){

		/* Default decode function */
		/*
			Parameters:
			
			$imagename		string					Filename (incl. path) of input image
			$verbose		0=false (default), 1=true		Direct output of extracted information
			$compress		0=false (default), 1=true		Compress input text
			$decrypt		0=false (default), 1=true		AES-256 decryption
			$passphrase		string					Decryption key
			$vertical		0=false (default), 1=true		If true, decode steganogram scanning from top to bottom, left to right (columnwise).
											If false, decode steganogram scanning from left to right, top to bottom (linewise).		
		*/

		
		$this->loadPng($imagename);
		$output = "";
		$output = $this->extractText($compress,$decrypt,$passphrase,$vertical);

		/* If verbose flag is set, echo message */
		if ($verbose == 1){ echo $output; };
		
		/* Deliver message as return value */
		return $output;
		
	}


	public function __construct() {

		/* Empty constructor */
   
	}


}

?>
