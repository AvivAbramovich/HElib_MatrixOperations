//  Created by Aviv Abramovich on 16/10/15.
//  Copyright (c) 2015 Aviv Abramovich. All rights reserved.
/*
 Matrices_Multiplication.cpp
 This code demonstrating how to encrypt, multiply and decrypt and print matrices
 */

#include "Matrices.h"
#include <sys/time.h>


/* Timers variables and methods*/
time_t time_begin, time_stop;
clock_t clock_begin, clock_stop;

void resetTimers(string label=""){
    if(label.compare("")!=0)
        cout << label << endl;
    time(&time_begin);
    clock_begin = clock();
}
void stopTimers(string label=""){
    time(&time_stop);
    clock_stop = clock(); //stop the clocks
    if(label.compare("")!=0)
        cout << "It took " << difftime(time_stop, time_begin) << " seconds and " << clock_stop-clock_begin<< " clock ticks " << label << endl;
}

bool isPrime(long num){
    if(num < 2)
        return false;
    for(unsigned int i=2; i*i <= num; i++){
        if(num%i == 0)
            return false;
    }
    return true;
}

long power(long base, long exponent){
	if(exponent == 1)
		return base;
	long res = power(base, exponent/2);
	return res*res*(exponent%2 ? base : 1);
}

int main(){
    long m, r, p, L, c, w, s, d, security, enc1, enc2, dec, encMul, ptMul, recommended;
    char tempChar;
    bool toEncMult = false, toPrint = false, debugMul = false, toSave = false;
    
    //Scan parameters
    
    cout << "Enter HElib's keys paramter. Enter zero for the recommended values" << endl;
    
    while(true){
        cout << "Enter the field of the computations (a prime number): ";
        cin >> p;
        if(isPrime(p))
            break;
        cout << "Error! p must be a prime number! " << endl;
    }
    while(true){
        recommended = 1;
        cout << "Enter r (recommended " << recommended <<"): ";
        cin >> r;
        if(r == 0)
            r = recommended;
        if(r > 0)
            break;
        cout << "Error! r must be a positive number!" << endl;
    }
    while(true){
        recommended = 16;
        cout << "Enter L (recommended " << recommended <<"): ";
        cin >> L;
        if(L == 0)
            L = recommended;
        if(L > 0)
            break;
        cout << "Error! L must be a positive number!" << endl;
    }
    while(true){
        recommended = 3;
        cout << "Enter c (recommended " << recommended <<"): ";
        cin >> c;
        if(c == 0)
            c = recommended;
        if(c > 0)
            break;
        cout << "Error! c must be a positive number!" << endl;
    }
    while(true){
        recommended = 128;
        cout << "Enter security (recommended " << recommended << "): ";
        cin >> security;
        if(security == 0)
            security = recommended;
        if(security > 0)
            break;
        cout << "Error! security must be a positive number " << endl;
    }
    while(true){
        recommended = 64;
        cout << "Enter w (recommended " << recommended <<"): ";
        cin >> w;
        if(w == 0)
            w = recommended;
        if(w > 1)
            break;
        cout << "Error! w must be a positive number!" << endl;
    }
    while(true){
        recommended = 0;
        cout << "Enter d (recommended " << recommended <<"): ";
        cin >> d;
        if(d >= 0)
            break;
        cout << "Error! d must be a positive or zero!" << endl;
    }
    while(true){
        recommended = 0;
        cout << "Enter s (recommended " << recommended <<"): ";
        cin >> s;
        if(s >= 0)
            break;
        cout << "Error! s must be a positive or zero!" << endl;
    }
    
    cout << "Generating public and secret keys..." << endl;
    resetTimers();
    ZZX G;
    m = FindM(security,L,c,p, d, s, 0);
    FHEcontext context(m, p, r);
    // initialize context
    buildModChain(context, L, c);
    // modify the context, adding primes to the modulus chain
    FHESecKey secretKey(context);
    // construct a secret key structure
    const FHEPubKey& publicKey = secretKey;
    // an "upcast": FHESecKey is a subclass of FHEPubKey
    
    //if(0 == d)
    G = context.alMod.getFactorsOverZZ()[0];
    
    secretKey.GenSecKey(w);
    // actually generate a secret key with Hamming weight w
    
    addSome1DMatrices(secretKey);
    EncryptedArray ea(context, G);
    // constuct an Encrypted array object ea that is
    // associated with the given context and the polynomial G
    
    long nslots = ea.size();
	long field = power(p,r);
    cout << "nslots: " << nslots << endl ;
    cout << "Computations will be modulo " << field << endl;
    cout << "Estimated security: " << context.securityLevel() << endl;
    
    stopTimers("to generate keys");
    
    /*
     the test: multiply 2 matrices, mat1*mat2 when m1 is Sz1*Sz2 matrix and mat2 is Sz2*Sz3
     */
    
    /*  ---------------- Get the matrices size from the user -------------------- */
    unsigned int Sz1, Sz2, Sz3;
    while(true){
        cout << "Enter the numbers of rows in the first matrix: ";
        cin >> Sz1;
        if(Sz1 > 0 && Sz1 <= nslots)
            break;
        cout << "Invalid input! The value must be greater than zero and less than " << nslots << endl;
    }
    while(true){
        cout << "Enter the numbers of cols in the first matrix (that is also the number of rows in the second matrix): ";
        cin >> Sz2;
        if(Sz2 > 0 && Sz2 <= nslots)
            break;
        cout << "Invalid input! The value must be greater than zero and less than " << nslots << endl;
    }
    while(true){
        cout << "Enter the numbers of columns in the second matrix: ";
        cin >> Sz3;
        if(Sz3 > 0 && Sz3 <= nslots)
            break;
        cout << "Invalid input! The value must be greater than zero and less than " << nslots << endl;
    }
    
    MatSize origSize1(Sz1,Sz2), origSize2(Sz2,Sz3);
    PTMatrix PTmat1(origSize1/*,p*/), PTmat2(origSize2/*,p*/);  //random matrix in size origSize1
    
    PTmat1.print();
    PTmat2.print();
    
    //encryptions
    cout << "Encrypting the first matrices..." << endl;
    resetTimers();
    EncryptedMatrix encMat1 = PTmat1.encrypt(ea, publicKey);
    stopTimers("to encrypt the first matrix");
    cout << "Encrypting the second matrices..." << endl;
    resetTimers();
    EncryptedMatrix encMat2 = PTmat2.encrypt(ea, publicKey);
    stopTimers("to encrypt the second matrix");
    
    //multiplication
    cout << "Multiplying the matrices..." << endl;
    resetTimers();
    encMat1*= encMat2;
    stopTimers("to multiply the matrices");
    
    cout << "Decrypting the result..." << endl;
    resetTimers();
    PTMatrix res = encMat1.decrypt(ea, secretKey);
    stopTimers("to decrypt the result");
    res.print("Solution: ");
    
    PTMatrix PTres = (PTmat1*PTmat2)%field;
    PTres.print("pt result: ");
    
    cout << "is correct? " << (res==PTres) << endl;
    return 0;
}
