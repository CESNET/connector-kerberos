package cz.zcu;

import org.identityconnectors.common.security.GuardedString;

import java.util.Arrays;

/**
 * Simple GuardedString accessor.
 * @author Milan Ševčík
 */
public class GuardedStringAccessor implements GuardedString.Accessor {
	private char[] myChars;

	@Override
	public void access(char[] chars) {
		if (chars != null) {
			myChars = new char[chars.length];
			System.arraycopy(chars, 0, myChars, 0, chars.length);
		}
	}

	public String getString() {
		if (myChars != null && myChars.length != 0) {
			return new String(myChars);
		} else {
			return null;
		}
	}

	public void clear() {
		if (myChars != null) {
			Arrays.fill(myChars, '\0');
			myChars = null;
		}
	}

	public static String getString(GuardedString string) {
		if (string != null) {
			GuardedStringAccessor accessor = new GuardedStringAccessor();
			string.access(accessor);

			String out = accessor.getString();
			accessor.clear();
			return out;
		} else {
			return null;
		}
	}
}
