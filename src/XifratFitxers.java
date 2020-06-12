

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class XifratFitxers {
	private static Scanner sc = new Scanner(System.in);
	private static final String[] invalidchars = { "\\", "/", ":", "*", "?", "<", ">", "|", "\"" }; // CARACTERS
																									// ESPECIALS QUE NO
																									// ACEPTA EL SISTEMA
																									// DE FITXERS DE
																									// WINDOWS

	public static void main(String[] args) {
		inici();
	}

	private static void inici() {
		String opcio = "0";
		while ((!opcio.equals("1")) && (!opcio.equals("2")) && (!opcio.equals("3"))) {
			System.out.println("ESCRIU EL VALOR NUMÈRIC AMB LA OPCIÓ DESITJADA: ");
			System.out.println("    1. XIFRAR    2.DESXIFRAR    3.SORTIR");
			opcio = sc.nextLine();
		}
		if (opcio.equals("1"))
			xifrar();
		else if (opcio.equals("2"))
			desxifrar();
		else
			System.exit(1);
	}

	private static void xifrar() {
		// FUNCIO PER DEMANAR LA RUTA DEL FITXER
		File ruta = getRuta();
		File desti = null;
		FileInputStream is = null;
		FileOutputStream os = null;
		String nom;

		System.out.println("Introdueix un nom pel fitxer xifrat: ");
		boolean correct;
		//DO WHILE
		do {
			//CRIDO LA FUNCIO PER AGAFAR EL NOM
			nom = getNom();
			String extensio = getFileExtension(ruta);
			desti = new File("fitxers\\" + nom + extensio);
			correct = true;
			try {
				if (!desti.createNewFile()) {
					System.out.println("El fitxer ja existeix, introdueix un altre nom: ");
					correct = false;
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		} while (!correct);

		try {
			is = new FileInputStream(ruta);
			os = new FileOutputStream(desti);
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		System.out.println("Introdueix la clau per xifrar el fitxer: ");
		String passwd;
		passwd = sc.nextLine();
		while (passwd.length() > 24) {
			//ESTABLEIXO UN LIMIT DE CARACTERS PERQUE LA CONTRASENYA DE 128 BITS, SI TE NUMEROS I SIMBOLS, CABRAN COM A MAXIM 24 CARACTERS
			System.out.println("La clau no pot superar els 24 caràcters");
			passwd = sc.nextLine();
		}

		SecretKey sKey = generateKey(passwd);

		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, sKey);

			CipherOutputStream cos = new CipherOutputStream(os, cipher);
			//CRIDO A LA FUNCIO PER COPIAR
			copy(is, cos);

			cos.close();

		} catch (Exception e) {
			System.out.println("Error xifrant les dades: " + e);
		}

		System.out.println("XIFRAT REALITZAT CORRECTAMENT");

	}

	private static void copy(InputStream is, OutputStream os) throws IOException {

		int i;
		byte[] b = new byte[1024];
		while ((i = is.read(b)) != -1) {
			os.write(b, 0, i);
		}

	}

	private static void desxifrar() {
		File ruta = getRuta();
		System.out.println("Introdueix un nom pel fitxer desxifrat");
		File desti = null;
		FileInputStream is = null;
		FileOutputStream os = null;
		String nom;
		String extensio;
		boolean correct;
		do {
			nom = getNom();
			extensio = getFileExtension(ruta);
			desti = new File("fitxers\\" + nom + extensio);
			correct = true;
			try {
				if (!desti.createNewFile()) {
					System.out.println("El fitxer ja existeix, introdueix un altre nom: ");
					correct = false;
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		} while (!correct);

		try {
			is = new FileInputStream(ruta);
			os = new FileOutputStream(desti);
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		System.out.println("Introdueix la clau del fitxer xifrat: ");
		String passwd;
		passwd = sc.nextLine();
		while (passwd.length() > 24) {
			System.out.println("La clau no pot superar els 24 caràcters");
			passwd = sc.nextLine();
		}

		SecretKey sKey = generateKey(passwd);

		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, sKey);

			CipherOutputStream cos = new CipherOutputStream(os, cipher);

			copy(is, cos);

			cos.close();

		} catch (Exception e) {
			System.out.println("Error xifrant les dades: " + e);
		}

		System.out.println("DESXIFRAT REALITZAT CORRECTAMENT");
	}

	private static SecretKey generateKey(String passwd) {
		SecretKey sKey = null;
		try {
			byte[] data = passwd.getBytes("UTF-8");
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] hash = md.digest(data);
			byte[] key = Arrays.copyOf(hash, (128 / 8));
			sKey = new SecretKeySpec(key, "AES");
		} catch (Exception ex) {
			System.out.println("Error generant la clau: " + ex);
		}

		return sKey;
	}

	private static File getRuta() {
		System.out.println("Introdueix la ruta del fitxer");
		File path = new File(sc.nextLine());

		while ((!path.exists()) || (path.isDirectory())) {
			System.out.println("No s'ha trobat el fitxer, introdueix la ruta correctament: ");
			path = new File(sc.nextLine());
		}
		return path;
	}

	private static String getNom() {
		String nom = null;
		boolean invalid = false;
		while (!invalid) {
			invalid = true;
			nom = sc.nextLine();
			for (String s : invalidchars) {
				if (nom.contains(s)) {
					invalid = false;
					System.out.println("No introdueixis caracters especials(\\/:*?<>|\")");
					break;
				}
			}
		}
		return nom;
	}

	// FUNCIO PER A AGAFAR LA EXTENSIO DEL FITXER ORIGINAL, PER CREAR LA COPIA
	private static String getFileExtension(File file) {
		String name = file.getName();
		int lastIndexOf = name.lastIndexOf(".");
		if (lastIndexOf == -1) {
			return ""; // empty extension
		}
		return name.substring(lastIndexOf);
	}

}