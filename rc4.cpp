#include <cmath>
#include <iostream>

int main();

char *encode(char *plaintext, std::size_t key);
char *decode(char *ciphertext, std::size_t key);

char *encode(char *plaintext, std::size_t key) {
    //Count size of plaintext
    int sizeo = 0;
    while (plaintext[sizeo] != '\0') {
        sizeo++;
    }

    //Initialize State Array
    unsigned char S[256];
    for (int z = 0; z < 256; z++) {
        S[z] = z;
    }

    int i = 0, j = 0, k = 0, r = 0, ctr = 0;
    char temp{};

    // Scramble the State Array
    for (i = 0; i < 256; i++) {
        k = i % 64;
        j = j + S[i] + ((key >> k) & 1);  // kth bit of key algorithm
        j = j % 256;
        temp = S[i];
        S[i] = S[j];  // swap
        S[j] = temp;
    }

    //Determine new size of return array
    //Need a multiple of 4 to correctly compute ascii armor
    int new_size = 0, n_chars = 0;
    if ((sizeo % 4 != 0)) {
        new_size = ((sizeo) + (4 - (sizeo % 4)));
        n_chars = (4 - (sizeo % 4));
    } else {
        new_size = (sizeo);
    }

    //Declare new return array and set all elements to the elements of the original plaintext
    char *updated_plaintext = new char[new_size];
    for (int m = 0; m < sizeo; m++) {
        updated_plaintext[m] = plaintext[m];
    }

    //Add null characters to make it a multiple of 4
    for (int l = 1; l <= n_chars; l++) {
        updated_plaintext[new_size - 1 - n_chars + l] = '\0';
    }

    ctr = 0;
    i = 0;

    //xor values of plaintext with the r value
    while (ctr < new_size) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        r = (S[i] + S[j]) % 256;

        updated_plaintext[ctr] ^= S[r];
        ctr++;
    }

    //ASCII ARMOR
    int asize = (new_size / 4) * 5 + 1;
    char *ascii_text = new char[asize];
    int ct = 4;

    for (int cnt = 0; (cnt + 4) <= new_size; cnt += 4) {
        unsigned int tempvar =
            ((static_cast<unsigned char>(updated_plaintext[cnt])) << 24) + ((static_cast<unsigned char>(updated_plaintext[cnt + 1])) << 16) + ((static_cast<unsigned char>(updated_plaintext[cnt + 2])) << 8) + (static_cast<unsigned char>(updated_plaintext[cnt + 3]));
        for (int m = 0; m < 5; m++) {
            ascii_text[ct - m] = (char)((tempvar % 85) + 33);
            tempvar = tempvar / 85;
        }
        ct += 5;
    }

    ascii_text[asize - 1] = '\0';
    return ascii_text;
}

char *decode(char *ciphertext, std::size_t key) {
    /*
	 STEP 1: UNDO ASCII ARMOR
	 - determine size of ciphertext
	 - determine how many groups of 32 bit integral values using the size found (one 32 bit integral value gives 5 coded chars)
	 - loop through each group
	 - from each group obtain a 32 bit integral value by undoing the +33 and /85 (to reverse use -33 and pow(85,)
	 - after finding the 32 bit integral value, there will be 4 8 bit chars from each of these values
	 - make new array to store all these 8 bit chars
	 - to find each of these 8 bit chars from the 32 bit integral value, undo the left shift
	 - when right shifting you also have to get rid of the values on the end
	 - take 1234 for example
	 - to get 2, you first have to shift left 1 and then right two to get 0002

	 STEP 2: DECODE KEY
	 - after you have all the new 8 bit chars, undo the encode function
	 - same thing as encode, find the r value and xor it

	 */

    int ct = 0;
    int size = 0;
    while (ciphertext[ct] != '\0') {
        size++;
        ct++;
    }

    //Undos ascii armor -> obtains 32 bit integral value
    int groups = (size / 5);
    unsigned int *a_int = new unsigned int[groups];
    int cntr = 0;

    for (int i = 0; i < groups; i++) {
        for (int m = 4; m >= 0; m--) {
            a_int[i] += ((ciphertext[cntr] - 33) * std::pow(85, m));
            cntr++;
        }
    }

    int n_size = groups * 4;
    int pos = 0;
    char *a_4int = new char[n_size];

    //Split 32 bit int into 4 8 bit chars
    for (int i = 0; i < groups; i++) {
        for (int j = 0; j < 4; j++) {
            a_4int[pos + j] = (a_int[i] << 8 * j) >> 24;
        }
        pos += 4;
    }
    unsigned char S[256];
    for (int z = 0; z < 256; z++) {
        S[z] = z;
    }

    int i = 0, j = 0, k = 0, r = 0, ctr = 0;
    char temp{};

    //Use same algorithm as encode to decode the characters
    for (i = 0; i < 256; i++) {
        k = i % 64;
        j = j + S[i] + ((key >> k) & 1);
        j = j % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }

    ctr = 0;
    i = 0;
    while (ctr < n_size) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        r = (S[i] + S[j]) % 256;
        a_4int[ctr] ^= S[r];
        ctr++;
    }

    a_4int[n_size] = '\0';
    return a_4int;
}

int main() {
    char str0[]{"string1"};
    char str1[]{"string2"};
    int key = 55555;

    std::cout << "Original String:" << std::endl;
    std::cout << "\"" << str0 << "\"" << std::endl;
    char *ciphertext{encode(str0, key)};
    std::cout << std::endl
              << "Ciphertext:" << std::endl;
    std::cout << "\"" << ciphertext << "\"" << std::endl;
    char *plaintext{decode(ciphertext, key)};
    std::cout << "\"" << plaintext << "\"" << std::endl;

    delete[] plaintext;
    delete[] ciphertext;
    ciphertext = nullptr;
    plaintext = nullptr;

    std::cout << "\"" << str1 << "\"" << std::endl;
    ciphertext = encode(str1, key);
    std::cout << "\"" << ciphertext << "\"" << std::endl;
    plaintext = decode(ciphertext, key);
    std::cout << "\"" << plaintext << "\"" << std::endl;

    delete[] plaintext;
    delete[] ciphertext;
    ciphertext = nullptr;
    plaintext = nullptr;

    return 0;
}
