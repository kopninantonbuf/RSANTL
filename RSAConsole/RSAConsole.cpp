#include <NTL/ZZ.h> // ���������� ���������� NTL � �������. ZZ ��������� �������� � �������� ������ ������� �������������� �����.
#include <time.h> // ������������ ���� time.h ����������� ��� ��������� ��������������� ����� � ����������� �� �������� �������.
#include <fstream> // ������������ ����, ��������������� ��� ������ � �������.


using namespace std;
using namespace NTL;

// �������� ��������� ����� ���� � ����� n �� 3, ����������� �������� ����� ������� ���.
bool isMod3(ZZ n)
{
	ZZ sum;
	while (n != 0)
	{
		sum += n % 10;
		n /= 10;
	}
	if (sum % 3 == 0)
		return true;
	else return false;
}

// ��������� ���������� ����� ������ bits ��� ������, ������� �� ������� �� 2, 3 � 5.
ZZ Get_Random_Prime(long bits)
{
	ZZ r = RandomLen_ZZ(bits);
	if (r % 2 == 0 || r % 5 == 0 || isMod3(r) == true)
		return Get_Random_Prime(bits);
	else return r;
}

// ��������� ���������� ����� ������ bits ���.
ZZ Get_Random(long bits)
{
	ZZ r = RandomLen_ZZ(bits);
	if (r <= 2)
		return Get_Random(bits);
	else return r;
}

// ���������� ��������� (a^(n-1/2)) mod n.
ZZ Exp_Mod(ZZ& a, ZZ& n)
{
	ZZ e = PowerMod(a, (n - 1) / 2, n);
	if (e - n == -1)
		return (ZZ)-1;
	else return PowerMod(a, (n - 1) / 2, n);
}

// ���������� ����� �������-���������. bits - ���������� ��� � ������� ������� �����, count_of_tests - ���������� ������, ������� ���������� ��������� ��� �����.
ZZ SolovayStrassen(long bits, int count_of_tests)
{
	ZZ a, n;
	bool b = false;

	while (b == false)
	{
		n = Get_Random_Prime(bits);

		for (int i = 0; i < count_of_tests; i++)
		{
			ZZ a;
			a = Get_Random(rand() % bits + 1);
			while (a > n)
				a = Get_Random(rand() % bits + 1);

			if (GCD(a, n) > 1)
				break;

			if (Exp_Mod(a, n) != Jacobi(a, n))
				break;

			if (i == 1)
				b = true;
		}
	}
	return n;
}

// � ���� ������� ������������ ��� ������� ����� p � q � ������� ����� �������-���������, ����������� �� ������������ n � �������� ������� ������. �������� sz ��������� ������ ����������� ������ ������������ �����.
void GenPrimes(ZZ& p, ZZ& q, ZZ& n, ZZ& eulerN, int sz, int count_of_tests)
{
	p = SolovayStrassen(sz, count_of_tests);
	q = SolovayStrassen(sz, count_of_tests);
	n = p * q;
	eulerN = (p - 1) * (q - 1);
}

// ������� GenKeys ������ �������� ���������� e � ���������� �� ��� ��������� ���������� d.
void GenKeys(ZZ& e, ZZ& d, ZZ& eulerN, long sz, int count_of_tests)
{
	do
		e = SolovayStrassen(sz, count_of_tests);
	while (e >= eulerN && GCD(e, eulerN) != 1);
	InvMod(d, e, eulerN);
}

// ������ ��������� � ��������� ������ � ��������� �����.
void SaveKey(ZZ& e, ZZ& d, ZZ& n)
{
	fstream fpublic, fprivate;
	fpublic.open("PublicKey.txt", ios::out);
	fprivate.open("PrivateKey.txt", ios::out);
	if (!fpublic || !fprivate)
	{
		cout << "������ ������ � ����. " << endl;
		system("pause");
		exit(0);
	}

	fpublic << e << "\n\n" << n;
	fprivate << d << "\n\n" << n;

	fpublic.close();
	fprivate.close();
}

// �������������� ������ � ���� ZZ.
ZZ StringToZZ(string str)
{
	ZZ number = conv<ZZ>(str[0]);
	long len = str.length();
	for (long i = 1; i < len; i++)
	{
		number *= 128;
		number += conv<ZZ>(str[i]);
	}

	return number;
}

// �������������� ���� ZZ � ������.
string ZZToString(ZZ num)
{
	long len = ceil(log(num) / log(128));
	char* str = new char[len];
	for (long i = len - 1; i >= 0; i--)
	{
		str[i] = conv<int>(num % 128);
		num /= 128;
	}
	str[len] = '\0';
	return (string)str;
}

// ������� ����������.
ZZ Encryption(string str, ZZ& e, ZZ& n)
{
	ZZ zz_from = StringToZZ(str);
	return PowerMod(zz_from % n, e, n);
}

// ������� ������������.
string Decryption(ZZ& cipherText, ZZ& d, ZZ& n)
{
	return ZZToString(PowerMod(cipherText % n, d, n));
}

const long SZ_PRIME = 1024;
const long SZ_E = 512;
const int CNT_OF_TESTS = 5;

int main()
{
	setlocale(LC_ALL, "Russian");
	SetSeed(to_ZZ((double)time(NULL))); // ������������� ���������� ��������������� �����.

	ZZ p, q, n, eulerN, e, d, cipherText;
	string plainText, decryptedCipherText;

	cout << "��������� ��������� ������� ����� p � q. \n";
	GenPrimes(p, q, n, eulerN, SZ_PRIME, CNT_OF_TESTS);
	cout << "p: " << p << endl << endl;
	cout << "q: " << q << endl << endl;
	cout << "n: " << n << endl << endl;
	cout << "euler(N): " << eulerN << endl << endl << "========================================" << endl;

	cout << "��������� �������� � ��������� ����������. \n";
	GenKeys(e, d, eulerN, SZ_E, CNT_OF_TESTS);
	cout << "e: " << e << endl << endl;
	cout << "d: " << d << endl << endl << "========================================" << endl;

	// ���������� ������ � �����.
	SaveKey(e, d, n);

	cout << "������� ���������, ������� ��������� ��������. \n";
	cout << "plainText: ";
	getline(cin, plainText, '\n');

	// ����������� ���������.
	cipherText = Encryption(plainText, e, n);
	cout << endl << "cipherText: " << cipherText << endl << endl;

	// ������������� ���������.
	decryptedCipherText = Decryption(cipherText, d, n);
	cout << "decryptedCipherText: " << decryptedCipherText << endl << endl;

	system("pause");
}
