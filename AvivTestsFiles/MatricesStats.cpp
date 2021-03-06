//  Created by Aviv Abramovich on 6/08/15.
//  Copyright (c) 2015 Aviv Abramovich. All rights reserved.
/*
 MatricesStats.cpp
 This code make a statistics about matrices multiplications, according to given security parameters
 */
#include "Grid.h"
#include <sys/time.h>

#define MAX_ITERS 20

/* Timers variables and methods*/
time_t time_begin, time_stop;
clock_t clock_begin, clock_stop;

typedef struct{
    long diffTime;
    long diffClock;
} TimeDiff;

void resetTimers(string label=""){
    if(label.compare("")!=0)
        cout << label << endl;
    time(&time_begin);
    clock_begin = clock();
}
TimeDiff stopTimers(string label=""){
    time(&time_stop);
    clock_stop = clock(); //stop the clocks
    TimeDiff ret = {difftime(time_stop, time_begin), clock_stop-clock_begin};
    if(label.compare("")!=0)
        cout << "It took " << ret.diffTime << " seconds and " << ret.diffClock << " clock ticks " << label << endl;
    return ret;
}

int Min(int a, int b) { return a < b ? a : b; }

int main(){
    srand(unsigned(time(NULL)));    //seed for random values
    
    cout << "-------------------------------------------------------------------------------------" << endl;
    cout << "|                        Testing matrices multiplication performance                |" << endl;
    cout << "-------------------------------------------------------------------------------------" << endl;
    int p;
    while(true){
        cout << "Enter p: ";
        cin >> p;
        if(p > 0){
            break;
        }
        cout << "Invalid input! p must be a positive integer!" << endl;
    }

    cout << "Generating public and secret keys..." << endl;
    resetTimers();
    long m=0, r=1; // Native plaintext space
    long L=16;          // Levels
    long c=3;           // Columns in key switching matrix
    long w=64;          // Hamming weight of secret key
    long d=0;
    long s = 0;  //minimum number of slots  [ default=0 ]
    long security = 128;
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
    
    stopTimers("to generate keys");
    
    cout << "HElib's keys parameters: " << endl;
    cout << "r: " << r << ", p: " << p << ", L: " << L <<", c: " << c << ", w: " << w << ", d: " << d << ", s: " << s << ", security: " << security << endl;
    
    long nslots = ea.size();
    cout << "nslots: " << nslots << endl ;
    cout << "Computations will be modulo " << p << endl;
    
    /* --------------------------- start of the intresting code ----------------------------------- */
    
    unsigned int numItters; //numbers of itterations per "experiment";
    unsigned int Sz1, Sz2, Sz3;
    
    vector<TimeDiff> encTime, mulTime, decTime; //vector of times and clock ticks per action
    
    //average time and clock ticks of actions per representation type
    TimeDiff RowsOrderEncAvg = {0,0}, RowsOrderMulAvg = {0,0}, RowsOrderDecAvg = {0,0};
    TimeDiff ColsOrderEncAvg = {0,0}, ColsOrderMulAvg = {0,0}, ColsOrderDecAvg = {0,0};
    TimeDiff DiagOrderEncAvg = {0,0}, DiagOrderMulAvg = {0,0}, DiagOrderDecAvg = {0,0};
    
    while(true){
        cout << "Enter num of iterations for each experiment: ";
        int temp;
        cin >> temp;
        if(temp > 0 && temp < MAX_ITERS){
            numItters = temp;
            break;
        }
        cout << "Invalid input! The number of iterations must be a positive integer and less than " << MAX_ITERS << endl;
    }
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
    
    //rows order stats
    encTime.resize(0); decTime.resize(0); mulTime.resize(0);    //empty vectors

    for(int i=0; i< numItters; i++){
        cout << "-------------- Rows order: test " << i+1 << " of " << numItters << " -----------------" << endl;
        PTMatrix mat1(origSize1, RowsOrder, Min(p,10)), mat2(origSize2, ColumnsOrder, Min(p,10));

        
        mat1.printDescription();
        mat2.printDescription();
        
        //encryptions
        cout << "Encrypting the first matrices..." << endl;
        resetTimers();
        EncryptedMatrix encMat1(mat1.encrypt(ea, publicKey));
        encTime.push_back(stopTimers("to encrypt the first matrix"));
        cout << "Encrypting the second matrices..." << endl;
        resetTimers();
        EncryptedMatrix encMat2(mat2.encrypt(ea, publicKey));
        encTime.push_back(stopTimers("to encrypt the second matrix"));
        
        //multiplication
        cout << "Multiplying the matrices..." << endl;
        resetTimers();
        EncryptedMatrix encRes(encMat1*encMat2);
        mulTime.push_back(stopTimers("to multiply the matrices"));
        
        cout << "Decrypting the result..." << endl;
        resetTimers();
        PTMatrix res(encRes.decrypt(ea, secretKey));
        decTime.push_back(stopTimers("to decrypt the result"));
        cout << "Solution: " << endl;
        res.changeMatrixRepresentation(RowsOrder);
        res.printDescription();
    }
    
    for(int i=0; i < encTime.size(); i++){
        RowsOrderEncAvg.diffTime += encTime[i].diffTime;
        RowsOrderEncAvg.diffClock += encTime[i].diffClock;
    }
    RowsOrderEncAvg.diffTime /= encTime.size();
    RowsOrderEncAvg.diffClock /= encTime.size();
    
    for(int i=0; i < mulTime.size(); i++){
        RowsOrderMulAvg.diffTime += mulTime[i].diffTime;
        RowsOrderMulAvg.diffClock += mulTime[i].diffClock;
    }
    RowsOrderMulAvg.diffTime /= mulTime.size();
    RowsOrderMulAvg.diffClock /= mulTime.size();
    
    for(int i=0; i < decTime.size(); i++){
        RowsOrderDecAvg.diffTime += decTime[i].diffTime;
        RowsOrderDecAvg.diffClock += decTime[i].diffClock;
    }
    RowsOrderDecAvg.diffTime /= decTime.size();
    RowsOrderDecAvg.diffClock /= decTime.size();
    
    cout << "-------------------------------------------------------------------------------------" << endl;
    cout << "|                             Finished Rows Order Experiment                        |" << endl;
    cout << "| Encryption Time Average : " << RowsOrderEncAvg.diffTime << " Seconds.   " << RowsOrderEncAvg.diffClock << " Clock Ticks." << endl;
    cout << "| Multiplication Time Average : " << RowsOrderMulAvg.diffTime << " Seconds.   " << RowsOrderMulAvg.diffClock << " Clock Ticks." << endl;
    cout << "| Decryption Time Average : " << RowsOrderDecAvg.diffTime << " Seconds.   " << RowsOrderDecAvg.diffClock << " Clock Ticks." << endl;
    cout << "-------------------------------------------------------------------------------------" << endl;
    
    //columns order stats
    encTime.resize(0), decTime.resize(0), mulTime.resize(0);    //empty vectors
    
    for(int i=0; i< numItters; i++){
        cout << "-------------- Columns order: test " << i+1 << " of " << numItters << " -----------------" << endl;
        PTMatrix mat1(origSize1, ColumnsOrder, Min(p,10)), mat2(origSize2, ColumnsOrder, Min(p,10));
        
        //mat1.changeMatrixRepresentation(ColumnsOrder);
        //mat2.changeMatrixRepresentation(ColumnsOrder);
        
        mat1.printDescription();
        mat2.printDescription();
        
        //encryptions
        cout << "Encrypting the first matrices..." << endl;
        resetTimers();
        EncryptedMatrix encMat1(mat1.encrypt(ea, publicKey));
        encTime.push_back(stopTimers("to encrypt the first matrix"));
        cout << "Encrypting the second matrices..." << endl;
        resetTimers();
        EncryptedMatrix encMat2(mat2.encrypt(ea, publicKey));
        encTime.push_back(stopTimers("to encrypt the second matrix"));
        
        //multiplication
        cout << "Multiplying the matrices..." << endl;
        resetTimers();
        EncryptedMatrix encRes(encMat1*encMat2);
        mulTime.push_back(stopTimers("to multiply the matrices"));
        
        cout << "Decrypting the result..." << endl;
        resetTimers();
        PTMatrix res(encRes.decrypt(ea, secretKey));
        decTime.push_back(stopTimers("to decrypt the result"));
        cout << "Solution: " << endl;
        res.changeMatrixRepresentation(RowsOrder);
        res.printDescription();
    }
    
    for(int i=0; i < encTime.size(); i++){
        ColsOrderEncAvg.diffTime += encTime[i].diffTime;
        ColsOrderEncAvg.diffClock += encTime[i].diffClock;
    }
    ColsOrderEncAvg.diffTime /= encTime.size();
    ColsOrderEncAvg.diffClock /= encTime.size();
    
    for(int i=0; i < mulTime.size(); i++){
        ColsOrderMulAvg.diffTime += mulTime[i].diffTime;
        ColsOrderMulAvg.diffClock += mulTime[i].diffClock;
    }
    ColsOrderMulAvg.diffTime /= mulTime.size();
    ColsOrderMulAvg.diffClock /= mulTime.size();
    
    for(int i=0; i < decTime.size(); i++){
        ColsOrderDecAvg.diffTime += decTime[i].diffTime;
        ColsOrderDecAvg.diffClock += decTime[i].diffClock;
    }
    ColsOrderDecAvg.diffTime /= decTime.size();
    ColsOrderDecAvg.diffClock /= decTime.size();
    
    cout << "-------------------------------------------------------------------------------------" << endl;
    cout << "|                             Finished Columns Order Experiment                        |" << endl;
    cout << "| Encryption Time Average : " << ColsOrderEncAvg.diffTime << " Seconds.   " << ColsOrderEncAvg.diffClock << " Clock Ticks." << endl;
    cout << "| Multiplication Time Average : " << ColsOrderMulAvg.diffTime << " Seconds.   " << ColsOrderMulAvg.diffClock << " Clock Ticks." << endl;
    cout << "| Decryption Time Average : " << ColsOrderDecAvg.diffTime << " Seconds.   " << ColsOrderDecAvg.diffClock << " Clock Ticks." << endl;
    cout << "-------------------------------------------------------------------------------------" << endl;

    //diagonal order stats
    encTime.resize(0), decTime.resize(0), mulTime.resize(0);    //empty vectors
    
    for(int i=0; i< numItters; i++){
        cout << "-------------- Diagonal order: test " << i+1 << " of " << numItters << " -----------------" << endl;
        PTMatrix mat1(origSize1, DiagonalOrder, Min(p,10)), mat2(origSize2, ColumnsOrder, Min(p,10));
        
        mat1.printDescription();
        mat2.printDescription();
        
        //encryptions
        cout << "Encrypting the first matrices..." << endl;
        resetTimers();
        EncryptedMatrix encMat1(mat1.encrypt(ea, publicKey));
        encTime.push_back(stopTimers("to encrypt the first matrix"));
        cout << "Encrypting the second matrices..." << endl;
        resetTimers();
        EncryptedMatrix encMat2(mat2.encrypt(ea, publicKey));
        encTime.push_back(stopTimers("to encrypt the second matrix"));
        
        //multiplication
        cout << "Multiplying the matrices..." << endl;
        resetTimers();
        EncryptedMatrix encRes(encMat1*encMat2);
        mulTime.push_back(stopTimers("to multiply the matrices"));
        
        cout << "Decrypting the result..." << endl;
        resetTimers();
        PTMatrix res(encRes.decrypt(ea, secretKey));
        decTime.push_back(stopTimers("to decrypt the result"));
        cout << "Solution: " << endl;
        res.changeMatrixRepresentation(RowsOrder);
        res.printDescription();

    }
    
    for(int i=0; i < encTime.size(); i++){
        DiagOrderEncAvg.diffTime += encTime[i].diffTime;
        DiagOrderEncAvg.diffClock += encTime[i].diffClock;
    }
    DiagOrderEncAvg.diffTime /= encTime.size();
    DiagOrderEncAvg.diffClock /= encTime.size();
    
    for(int i=0; i < mulTime.size(); i++){
        DiagOrderMulAvg.diffTime += mulTime[i].diffTime;
        DiagOrderMulAvg.diffClock += mulTime[i].diffClock;
    }
    DiagOrderMulAvg.diffTime /= mulTime.size();
    DiagOrderMulAvg.diffClock /= mulTime.size();
    
    for(int i=0; i < decTime.size(); i++){
        DiagOrderDecAvg.diffTime += decTime[i].diffTime;
        DiagOrderDecAvg.diffClock += decTime[i].diffClock;
    }
    DiagOrderDecAvg.diffTime /= decTime.size();
    DiagOrderDecAvg.diffClock /= decTime.size();
    
    cout << "-------------------------------------------------------------------------------------" << endl;
    cout << "|                             Finished Diagonal Order Experiment                        |" << endl;
    cout << "| Encryption Time Average : " << DiagOrderEncAvg.diffTime << " Seconds.   " << DiagOrderEncAvg.diffClock << " Clock Ticks." << endl;
    cout << "| Multiplication Time Average : " << DiagOrderMulAvg.diffTime << " Seconds.   " << DiagOrderMulAvg.diffClock << " Clock Ticks." << endl;
    cout << "| Decryption Time Average : " << DiagOrderDecAvg.diffTime << " Seconds.   " << DiagOrderDecAvg.diffClock << " Clock Ticks." << endl;
    cout << "-------------------------------------------------------------------------------------" << endl;
    
    cout << endl << endl << endl << endl << endl << endl;
    
    cout << "-------------------------------------------------------------------------------------" << endl;
    cout << "-----------------------------------------SUMMARY-------------------------------------" << endl;
    cout << "|" << endl;
    cout << "| HElib's keys parameters: " << endl;
    cout << "| r: " << r << ", p: " << p <<", L: " << L <<", c: " << c << ", w: " << w << ", d: " << d << ", s: " << s << ", security: " << security << endl;
    cout << "|" << endl;
    cout << "| Matrices Multiplication: First matrix in size " << Sz1 << "x" <<Sz2 << ", second matrix in size " << Sz2 << "x" << Sz3 << endl;
    cout << "|" << endl;
    cout << "|                                  Rows Rows Order Result" << endl;
    cout << "| Encryption Time Average : " << RowsOrderEncAvg.diffTime << " Seconds.   " << RowsOrderEncAvg.diffClock << " Clock Ticks." << endl;
    cout << "| Multiplication Time Average : " << RowsOrderMulAvg.diffTime << " Seconds.   " << RowsOrderMulAvg.diffClock << " Clock Ticks." << endl;
    cout << "| Decryption Time Average : " << RowsOrderDecAvg.diffTime << " Seconds.   " << RowsOrderDecAvg.diffClock << " Clock Ticks." << endl;
    cout << "|" << endl;
    cout << "|" << endl;
    cout << "|                                   Columns Order Results" << endl;
    cout << "| Encryption Time Average : " << ColsOrderEncAvg.diffTime << " Seconds.   " << ColsOrderEncAvg.diffClock << " Clock Ticks." << endl;
    cout << "| Multiplication Time Average : " << ColsOrderMulAvg.diffTime << " Seconds.   " << ColsOrderMulAvg.diffClock << " Clock Ticks." << endl;
    cout << "| Decryption Time Average : " << ColsOrderDecAvg.diffTime << " Seconds.   " << ColsOrderDecAvg.diffClock << " Clock Ticks." << endl;
    cout << "|" << endl;
    cout << "|" << endl;
    cout << "|                                   Diagonal Order Results" << endl;
    cout << "| Encryption Time Average : " << DiagOrderEncAvg.diffTime << " Seconds.   " << DiagOrderEncAvg.diffClock << " Clock Ticks." << endl;
    cout << "| Multiplication Time Average : " << DiagOrderMulAvg.diffTime << " Seconds.   " << DiagOrderMulAvg.diffClock << " Clock Ticks." << endl;
    cout << "| Decryption Time Average : " << DiagOrderDecAvg.diffTime << " Seconds.   " << DiagOrderDecAvg.diffClock << " Clock Ticks." << endl;
    cout << "|" << endl;
    cout << "-------------------------------------------------------------------------------------" << endl;
    cout << "-------------------------------------------------------------------------------------" << endl;
    
    return 0;
}