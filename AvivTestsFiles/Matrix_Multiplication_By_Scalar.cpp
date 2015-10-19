//  Created by Aviv Abramovich on 16/10/15.
//  Copyright (c) 2015 Aviv Abramovich. All rights reserved.
/*
 Matrix_Multiplication_By_Scalar.cpp
 This code demonstrating how to multiply an encrypted matrix by scalar
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

long power(long p, long r){
    if(r ==0)
        return 1;
    long ret = power(p, r/2);
    return ret*ret*(r%2 ? p : 1);
}

int main(){
    long m, r, p, L, c, w, s, d, security, enc, dec, encMul, recommended;
    char tempChar;
    bool toPrint = false, toSave = false;
    
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
    
    long nslots = ea.size(), field = power(p,r);
    cout << "nslots: " << nslots << endl ;
    cout << "Computations will be modulo " << field << endl;
    cout << "m: " << m << endl;
    
    unsigned int sz1, sz2, num;
    while(true){
        cout << "Enter number of rows in the matrix: ";
        cin >> sz1;
        if(sz1 > 1 && sz1 <= nslots)
            break;
        cout << "Error! the value must be between 1 to " << nslots << "!" << endl;
    }
    while(true){
        cout << "Enter number of columns in the matrix: ";
        cin >> sz2;
        if(sz1 > 2 && sz2 <= nslots)
            break;
        cout << "Error! the value must be between 1 to " << nslots << "!" << endl;
    }
    cout << "Enter the number you want to multiply the matrix by: ";
    cin >> num;
    
    MatSize sz(sz1, sz2);
    PTMatrix PTmat(sz,field);  //random matrix in size origSize1
    
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
    if(toPrint)
        PTmat.print();
    
    if(toSave){
        ofstream out_mat("mat.txt");
        PTmat.save(out_mat);
        out_mat.close();
    }
    
    //encryptions
    cout << "Encrypting the matrix..." << endl;
    resetTimers();
    EncryptedMatrix encMat = PTmat.encrypt(ea, publicKey);
    enc = stopTimers("to encrypt the first matrix");
    
    //Multiply by constant
    cout << "Multiplying the matricex by constant..." << endl;
    resetTimers();
    encMat *= num;
    encMul = stopTimers("to multiply the matrix");
    
    cout << "Decrypting the result..." << endl;
    resetTimers();
    PTMatrix res = encMat.decrypt(ea, secretKey);
    dec = stopTimers("to decrypt the result");
    if(toPrint)
        res.print("Solution: ");
    
    PTMatrix PTres = PTmat;
    for(unsigned int i=1; i < num; i++){
        PTres += PTmat;
    }
    PTres %= field;
    if(toPrint)
        PTres.print("pt Solution: ");
    
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
    cout << "It took " << enc << " clock ticks to encrypt the matrix" << endl;
    cout << "It took " << dec << " clock ticks to decrypt the result" << endl;
    cout << "It took " << encMul << " clock ticks to add the encrypted matrices" << endl;
    cout << "is correct? " << (res==PTres) << endl;

    return 0;
}