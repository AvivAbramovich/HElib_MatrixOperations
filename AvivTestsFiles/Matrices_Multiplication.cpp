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

int main(){
    /* On our trusted system we generate a new key
     * (or read one in) and encrypt the secret data set.
     */
    cout << "Generating public and secret keys..." << endl;
    resetTimers();
    long m=0, r=1; // Native plaintext space
    int p = 65539; // Computations will be 'modulo p'
    long L=16;          // Levels
    long c=3;           // Columns in key switching matrix
    long w=64;          // Hamming weight of secret key
    //long d=0;
    //long s = 0;  //minimum number of slots  [ default=0 ]
    //long security = 128;
    ZZX G;
    //m = FindM(security,L,c,p, d, s, 0);
    cout << "enter m: " << endl;
    cin >> m;
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
    cout << "nslots: " << nslots << endl ;
    cout << "Computations will be modulo " << p << endl;
    
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
    
    PTMatrix PTres = (PTmat1*PTmat2)/*%p*/;
    PTres.print("pt result: ");
    
    cout << "is correct? " << (res==PTres) << endl;
    return 0;
}