//  Created by Aviv Abramovich on 6/08/15.
//  Copyright (c) 2015 Aviv Abramovich. All rights reserved.
/*
 Test_AvivGrid.cpp
 This code demonstrating how to encrypt, multiply and decrypt and print matrices
 */

#include "Grid.h"
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
    cout << "Enter m: ";
    cin >> m;
    while(m <= 0){
        cout << "Enter a positive m" << endl;
        cin >> m;
    }
    ZZX G;
    //m = FindM(security,L,c,p, d, s, 0);
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
    
    stopTimers("to generate keys");
    
    long nslots = ea.size();
    cout << "nslots: " << nslots << endl ;
    cout << "Computations will be modulo " << p << endl;
    
    /* --------------------------- start of the intresting code ----------------------------------- */
    
    unsigned int Sz1, Sz2, Sz3;
    while(true){
        cout << "Enter the numbers of rows in the first matrix: ";
        cin >> Sz1;
        if(Sz1 > 0)
            break;
        cout << "Invalid input! The value must be a positive integer" << endl;
    }
    while(true){
        cout << "Enter the numbers of cols in the first matrix (that is also the number of rows in the second matrix): ";
        cin >> Sz2;
        if(Sz2 > 0)
            break;
        cout << "Invalid input! The value must be a positive integer" << endl;
    }
    while(true){
        cout << "Enter the numbers of columns in the second matrix: ";
        cin >> Sz3;
        if(Sz3 > 0)
            break;
        cout << "Invalid input! The value must be a positive integer" << endl;
    }
    
    MatSize blockSize(nslots, nslots);
    PTMatrix mat1(MatSize(Sz1,Sz2)), mat2(MatSize(Sz2, Sz3));    //creating a random matrices at size m1size and m2Size
    
    //deconstruct the matrices to blocks
    cout << "Diconstruct Mat1 to a grid..." << endl;
    resetTimers();
    PTMatrixGrid PTgrid1(mat1, blockSize);
    stopTimers("to diconstruct mat1 to a grid");
    cout << "Diconstruct Mat2 to a grid..." << endl;
    resetTimers();
    PTMatrixGrid PTgrid2(mat2, blockSize);
    stopTimers("to diconstruct mat2 to a grid");

    //print the matrices
    mat1.print("Mat1:");
    cout << "the small matrices:" << endl;
    for(unsigned int i=0, l1 = PTgrid1.size(); i < l1; i++)
        for(unsigned int j=0, l2 = PTgrid1[i].size(); j < l2; j++){
            cout << "mat1["<<i<<","<<j<<"]:" << endl;
            PTgrid1[i][j].print();
        }
    mat2.print("Mat2:");
    cout << "the small matrices:" << endl;
    for(unsigned int i=0, l1 = PTgrid2.size(); i < l1; i++)
        for(unsigned int j=0, l2 = PTgrid2[i].size(); j < l2; j++){
            cout << "mat2["<<i<<","<<j<<"]:" << endl;
            PTgrid2[i][j].print();
        }
    //decrypting the matrices
    cout << "Encrypting the mat1's grides..." << endl;
    resetTimers();
    EncryptedMatrixGrid encGrid1 = PTgrid1.encrypt(ea, publicKey);
    stopTimers("to encrypt mat1's grid");
    
    cout << "Encrypting the mat2's grides..." << endl;
    resetTimers();
    EncryptedMatrixGrid encGrid2 = PTgrid2.encrypt(ea, publicKey);
    stopTimers("to encrypt mat2's grid");
    
    cout << "Multiplying the encrypted grides..." << endl;
    resetTimers();
    EncryptedMatrixGrid encMult = encGrid1*encGrid2;
    stopTimers("to multiply the matrices grids");
    
    //decrypting the result
    cout << "Decrypting the encrypted grides..." << endl;
    resetTimers();
    PTMatrixGrid res = encMult.decrypt(ea, secretKey);
    stopTimers("to decrypt the result");
    
    //re-unite the grid
    cout << "The reuinted matrix" << endl;
    //PTMatrix reuinted = res.resize(m1Size*m2Size, m1blockSize*m2blockSize).reunion();
    PTMatrix reuinted = res.reunion();
    reuinted.print("Result:");
    
    PTMatrix PTres = (mat1*mat2)%p;
    PTres.print();
    
    cout << "is correct? " << (PTres == reuinted) << endl;
    return 0;
}