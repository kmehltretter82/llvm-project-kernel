// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-indent -verify %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wall -Wno-misleading-indentation -verify=wall %s

// wall-no-diagnostics

int step(int);

int misplaced(int a)
{
	int b = a;

	if (a) // expected-note {{previous statement is here}}
		b = step(b);
		b += 2; // expected-warning {{this statement is indented differently from the statement before it in the same block}}
	return b;
}

int spaces(int a)
{
	int b = a;
        b += 1; // expected-note {{previous statement is here}}
	 b += 2; // expected-warning {{this statement is indented differently}}
	return b;
}

int labels(int a)
{
	int b = a;

	if (!a)
		goto out;
	b = step(b);
	switch (b) {
	case 1:
		b = 2;
		break;
	default:
		break;
	}
out:
	return b;
}

#define TWO(x) do { x = step(x); x = step(x); } while (0)

int macros(int a)
{
	int b = a; TWO(b);
	TWO(b);
	return b;
}
