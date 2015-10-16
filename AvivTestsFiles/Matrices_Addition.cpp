//  Created by Aviv Abramovich on 16/10/15.
//  Copyright (c) 2015 Aviv Abramovich. All rights reserved.
/*
 Matrices_Addition.cpp
 This code demonstrating how to adding encrypted matrices
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
long stopTimers(string label=""){
    time(&time_stop);
    clock_stop = clock(); //stop the clocks
    if(label.compare("")!=0)
        cout << "It took " << difftime(time_stop, time_begin) << " seconds and " << clock_stop-clock_begin<< " clock ticks " << label << endl;
    return clock_stop-clock_begin;
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

int main(){
    /*
    long m=0, r=1; // Native plaintext space
    int p = 65539; // Computations will be 'modulo p'
    long L=16;          // Levels
    long c=3;           // Columns in key switching matrix
    long w=64;          // Hamming weight of secret key
    long d=0;
    long s = 0;  //minimum number of slots  [ default=0 ]
    long security = 128;*/
    long m, r, p, L, c, w, s, d, security, enc1, enc2, dec, encMul, ptMul, recommended;
    char tempChar;
    bool toPrint = false, debugAdd = false, toSave = false;
    
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
        if(L > 1)
            break;
        cout << "Error! L must be a positive number!" << endl;
    }
    while(true){
        recommended = 3;
        cout << "Enter c (recommended " << recommended <<"): ";
        cin >> c;
        if(c == 0)
            c = recommended;
        if(c > 1)
            break;
        cout << "Error! c must be a positive number!" << endl;
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
    while(true){
        recommended = 128;
        cout << "Enter security (recommended " << recommended << "): ";
        cin >> security;
        if(security == 0)
            security = recommended;
        if(security >= 1)
            break;
        cout << "Error! security must be a positive number " << endl;
    }
    
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
    cout << "nslots: " << nslots << endl ;
    cout << "Computations will be modulo " << p << endl;
    cout << "m: " << m << endl;
    
    unsigned int sz1, sz2;
    while(true){
        cout << "Enter number of rows in the matrices: ";
        cin >> sz1;
        if(sz1 > 1 && sz1 <= nslots)
            break;
        cout << "Error! the value must be between 1 to " << nslots << "!" << endl;
    }
    while(true){
        cout << "Enter number of columns in the matrices: ";
        cin >> sz2;
        if(sz1 > 2 && sz2 <= nslots)
            break;
        cout << "Error! the value must be between 1 to " << nslots << "!" << endl;
    }
    MatSize sz(sz1, sz2);
    PTMatrix PTmat1(sz,p), PTmat2(sz, p);  //random matrix in size origSize1
    
    while(true){
        cout << "Debug the addition steps?\nY for yesm N for no :";
        cin >> tempChar;
        if(tempChar == 'Y' || tempChar == 'y'){
            debugAdd = true;
            break;
        }
        if(tempChar == 'N' || tempChar == 'n'){
            debugAdd = false;
            break;
        }
        cout << "Error! invalid input!" << endl;
    }
    while(true){
        cout << "Print the matrices?" << endl;
        cout << "Y for yes, N for no: ";
        cin >> tempChar;
        if(tempChar == 'Y' || tempChar == 'y'){
            toPrint = true;
            break;
        }
        if(tempChar == 'N' || tempChar == 'n'){
            toPrint = false;
            break;
        }
        cout << "Error! invalid input!" << endl;
    }
    while(true){
        cout << "Save the matrices?" << endl;
        cout << "Y for yes, N for no: ";
        cin >> tempChar;
        if(tempChar == 'Y' || tempChar == 'y'){
            toSave = true;
            break;
        }
        if(tempChar == 'N' || tempChar == 'n'){
            toSave = false;
            break;
        }
        cout << "Error! invalid input!" << endl;
    }
    if(toPrint){
        PTmat1.print();
        PTmat2.print();
    }
    if(toSave){
        ofstream out_mat1("mat1.txt"), out_mat2("mat2.txt");
        PTmat1.save(out_mat1);
        PTmat2.save(out_mat2);
        out_mat1.close(); out_mat2.close();
    }
    
    //encryptions
    cout << "Encrypting the first matrices..." << endl;
    resetTimers();
    EncryptedMatrix encMat1 = PTmat1.encrypt(ea, publicKey);
    enc1 = stopTimers("to encrypt the first matrix");
    cout << "Encrypting the second matrices..." << endl;
    resetTimers();
    EncryptedMatrix encMat2 = PTmat2.encrypt(ea, publicKey);
    enc2 = stopTimers("to encrypt the second matrix");
    
    //addition
    cout << "Adding the matrices..." << endl;
    resetTimers();
    if(debugAdd)
        encMat1 = encMat1.debugAdd(encMat2); //same as encMat1 += encMat2 but print progress update
    else
        encMat1 += encMat2;
    encMul = stopTimers("to add the matrices");
    
    cout << "Decrypting the result..." << endl;
    resetTimers();
    PTMatrix res = encMat1.decrypt(ea, secretKey);
    dec = stopTimers("to decrypt the result");
    if(toPrint)
        res.print("Solution: ");
    
    resetTimers();
    PTMatrix PTres = (PTmat1 + PTmat2)%p;
    ptMul = stopTimers("to add the regular matrices");
    
    if(toSave){
        ofstream out_res("mat_res.txt"), out_ptRes("mat_pt_res.txt");
        res.save(out_res);
        PTres.save(out_ptRes);
        out_res.close(); out_ptRes.close();
    }
    
    //PTres.print("pt result: ");
    
    cout << "\n\n----------------------------------------Summary------------------------------ " << endl;
    cout << "p: " << p << ", r: " << r << ", L: " << L << ", c: " << c << ", w: " << w << ", d: " << d << ", s: " << s << ", security: " << security << endl;
    cout << "nslots: " << nslots << "\nm: " << m << endl;
    cout << "It took " << enc1 << " clock ticks to encrypt the first matrix" << endl;
    cout << "It took " << enc2 << " clock ticks to encrypt the second matrix" << endl;
    cout << "It took " << dec << " clock ticks to decrypt the result" << endl;
    cout << "It took " << ptMul << " clock ticks to add the regular matrices" << endl;
    cout << "It took " << encMul << " clock ticks to add the encrypted matrices" << endl;
    cout << "is correct? " << (res==PTres) << endl;

    return 0;
}