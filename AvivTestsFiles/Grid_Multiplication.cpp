//  Created by Aviv Abramovich on 16/10/15.
//  Copyright (c) 2015 Aviv Abramovich. All rights reserved.
/*
 Grid_Multiplication.cpp
 This code generate a random matrix, encrypt them into encrypted matrices grid and multiply them.
 The test also measuring the time it take to each operation
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
    
    cout << "This experiment check for different values of parameters, how much time it takes to encrypt and decrypt a \"full\" matrix (nslots*nslots), and multply 2 encrypted matrices\nAlso check for what size of matrices, the multiplication in the server on the encrypted data is faster than for the user than do all the work on his machine. Using this formula: N > n(P)*(2*Enc(P)+Dec(P)) when:\nP is the parameters\nn(P) is the nslots value for these values\nEnc(P) and Dec(P) is the time it takes to encrypt and decrypt the matrics in size nslots*nslots\nNOTE: this formula don't take into account the time it takes to send and recieve the data to and from the server, and the time it took to the server to do the actual multiplication\n" << endl;
    
    /*
    long m=0, r=1; // Native plaintext space
    int p = 65539; // Computations will be 'modulo p'
    long L=16;          // Levels
    long c=3;           // Columns in key switching matrix
    long w=64;          // Hamming weight of secret key
    long d=0;
    long s = 0;  //minimum number of slots  [ default=0 ]
    long security = 128;*/
    long m, r, p,L, c, w, s, d, security, enc1, enc2, dec, encMul, ptMul, recommended;
    char tempChar;
    bool toEncMult, toPrint;
    
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
    
    unsigned int sz1;
    while(true){
        cout << "Enter size of matrices: ";
        cin >> sz1;
        if(sz1 > 1)
            break;
        cout << "Error! the value must be a positive number!" << endl;
    }
    
    MatSize atom(nslots,nslots), sqr(sz1,sz1);
    PTMatrix mat1(sqr, field), mat2(sqr, field);
    PTMatrixGrid grid1(mat1, atom), grid2(mat2, atom);
    
    //save the grids
    //save to files
    ofstream outGrid1("grid1.txt"), outGrid2("grid2.txt");
    grid1.save(outGrid1);
    grid2.save(outGrid2);
    outGrid1.close(); outGrid2.close();
    
    while(true){
        cout << "To multiply the encrypted matrices? Not affecting the formula, just for statistic" << endl;
        cout << "Y for yes, N for no: ";
        cin >> tempChar;
        if(tempChar == 'Y' || tempChar == 'y'){
            toEncMult = true;
            break;
        }
        if(tempChar == 'N' || tempChar == 'n'){
            toEncMult = false;
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
    if(toPrint){
        mat1.print();
        mat2.print();
    }
    
    //encryptions
    cout << "Encrypting the first grid..." << endl;
    resetTimers();
    EncryptedMatrixGrid encGrid1 = grid1.encrypt(ea, publicKey);
    enc1 = stopTimers("to encrypt the first grid");
    cout << "Encrypting the second grid..." << endl;
    resetTimers();
    EncryptedMatrixGrid encGrid2 = grid2.encrypt(ea, publicKey);
    enc2 = stopTimers("to encrypt the second grid");
    
    //multiplication
    if(toEncMult){
        cout << "Multiplying the matrices..." << endl;
        resetTimers();
        encGrid1 *= encGrid2;
        //encMat1 = encMat1.debugMul(encMat2); //same as encMat1 *= encMat2 but print progress update
        encMul = stopTimers("to multiply the matrices");
    }
    
    cout << "Decrypting the result..." << endl;
    resetTimers();
    PTMatrixGrid res = encGrid1.decrypt(ea, secretKey);
    dec = stopTimers("to decrypt the result");
    PTMatrix reunionGrid = res.reunion();
    if(toPrint)
        reunionGrid.print("Solution: ");
    
    resetTimers();
    PTMatrix PTres = mat1.mulWithMod(mat2,field); //like (PTmat1*PTmat2)%p but do modulu after each multiplication to avoid overflow
    ptMul = stopTimers("to multiply the regular matrices");
    
    if(toPrint)
        PTres.print("pt result: ");
    
    //save to results
    ofstream outEncRes("encRes.txt"), outPTres("ptRes.txt");
    res.save(outEncRes);
    PTres.save(outPTres);
    outEncRes.close();
    outPTres.close();
    
    cout << "\n\n----------------------------------------Summary------------------------------ " << endl;
    cout << "p: " << p << ", r: " << r << ", L: " << L << ", c: " << c << ", w: " << w << ", d: " << d << ", s: " << s << ", security: " << security << endl;
    cout << "nslots: " << nslots << "\nm: " << m << endl;
    cout << "It took " << enc1 << " clock ticks to encrypt the first matrix" << endl;
    cout << "It took " << enc2 << " clock ticks to encrypt the second matrix" << endl;
    cout << "It took " << dec << " clock ticks to decrypt the result" << endl;
    cout << "It took " << ptMul << " clock ticks to multiply the regular matrices" << endl;
    if(toEncMult){
        cout << "It took " << encMul << " clock ticks to multiply the encrypted matrices" << endl;
        cout << "is correct? " << (reunionGrid==PTres) << endl;
    }

    return 0;
}