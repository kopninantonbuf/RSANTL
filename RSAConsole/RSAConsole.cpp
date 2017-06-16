#include <NTL/ZZ.h> // Подключаем библиотеку NTL к проекту. ZZ позволяет работать с большими целыми числами неограниченной длины.
#include <time.h> // Заголовочный файл time.h потребуется для генерации псевдослучайных чисел в зависимости от текущего времени.
#include <fstream> // Заголовочный файл, предназначенный для работы с файлами.


using namespace std;
using namespace NTL;

// Проверка делимости суммы цифр в числе n на 3, позволяющее откинуть числа кратные трём.
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

// Генерация случайного числа длиной bits бит такого, которое не делится на 2, 3 и 5.
ZZ Get_Random_Prime(long bits)
{
	ZZ r = RandomLen_ZZ(bits);
	if (r % 2 == 0 || r % 5 == 0 || isMod3(r) == true)
		return Get_Random_Prime(bits);
	else return r;
}

// Генерация случайного числа длиной bits бит.
ZZ Get_Random(long bits)
{
	ZZ r = RandomLen_ZZ(bits);
	if (r <= 2)
		return Get_Random(bits);
	else return r;
}

// Вычисление выражения (a^(n-1/2)) mod n.
ZZ Exp_Mod(ZZ& a, ZZ& n)
{
	ZZ e = PowerMod(a, (n - 1) / 2, n);
	if (e - n == -1)
		return (ZZ)-1;
	else return PowerMod(a, (n - 1) / 2, n);
}

// Реализация теста Соловея-Штрассена. bits - количество бит в искомом простом числе, count_of_tests - количество тестов, которое необходимо проделать для числа.
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

// В этой функции генерируются два простых числа p и q с помощью теста Соловея-Штрассена, вычисляется их произведение n и значение функции Эйлера. Параметр sz позволяет задать необходимый размер генерируемых чисел.
void GenPrimes(ZZ& p, ZZ& q, ZZ& n, ZZ& eulerN, int sz, int count_of_tests)
{
	p = SolovayStrassen(sz, count_of_tests);
	q = SolovayStrassen(sz, count_of_tests);
	n = p * q;
	eulerN = (p - 1) * (q - 1);
}

// Функция GenKeys создаёт открытую экспоненту e и генерирует по ней секретную экспоненту d.
void GenKeys(ZZ& e, ZZ& d, ZZ& eulerN, long sz, int count_of_tests)
{
	do
		e = SolovayStrassen(sz, count_of_tests);
	while (e >= eulerN && GCD(e, eulerN) != 1);
	InvMod(d, e, eulerN);
}

// Запись открытого и закрытого ключей в текстовые файлы.
void SaveKey(ZZ& e, ZZ& d, ZZ& n)
{
	fstream fpublic, fprivate;
	fpublic.open("PublicKey.txt", ios::out);
	fprivate.open("PrivateKey.txt", ios::out);
	if (!fpublic || !fprivate)
	{
		cout << "Ошибка записи в файл. " << endl;
		system("pause");
		exit(0);
	}

	fpublic << e << "\n\n" << n;
	fprivate << d << "\n\n" << n;

	fpublic.close();
	fprivate.close();
}

// Преобразование строки к типу ZZ.
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

// Преобразование типа ZZ к строке.
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

// Функция шифрования.
ZZ Encryption(string str, ZZ& e, ZZ& n)
{
	ZZ zz_from = StringToZZ(str);
	return PowerMod(zz_from % n, e, n);
}

// Функция дешифрования.
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
	SetSeed(to_ZZ((double)time(NULL))); // Инициализация генератора псевдослучайных чисел.

	ZZ p, q, n, eulerN, e, d, cipherText;
	string plainText, decryptedCipherText;

	cout << "Генерация случайных простых чисел p и q. \n";
	GenPrimes(p, q, n, eulerN, SZ_PRIME, CNT_OF_TESTS);
	cout << "p: " << p << endl << endl;
	cout << "q: " << q << endl << endl;
	cout << "n: " << n << endl << endl;
	cout << "euler(N): " << eulerN << endl << endl << "========================================" << endl;

	cout << "Генерация открытой и секретной экспоненты. \n";
	GenKeys(e, d, eulerN, SZ_E, CNT_OF_TESTS);
	cout << "e: " << e << endl << endl;
	cout << "d: " << d << endl << endl << "========================================" << endl;

	// Сохранение ключей в файлы.
	SaveKey(e, d, n);

	cout << "Введите сообщение, которое требуется передать. \n";
	cout << "plainText: ";
	getline(cin, plainText, '\n');

	// Кодирование сообщения.
	cipherText = Encryption(plainText, e, n);
	cout << endl << "cipherText: " << cipherText << endl << endl;

	// Декодирование сообщения.
	decryptedCipherText = Decryption(cipherText, d, n);
	cout << "decryptedCipherText: " << decryptedCipherText << endl << endl;

	system("pause");
}
