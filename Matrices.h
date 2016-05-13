//  Created by Aviv Abramovich on 15/09/15.
//  Copyright (c) 2015 Aviv Abramovich. All rights reserved.

#include <NTL/lzz_pXFactoring.h>
#include "FHE.h"
#include "EncryptedArray.h"
#include "replicate.h"
#include <fstream>
#include <sstream>
#include <sys/time.h>
#include <exception>

//This class help to manage the encrypted matrices sizes
class MatSize{
public:
    unsigned int rows;      //Num of rows in the matrix
    unsigned int columns;   //Num of Columns in the matrix
    
    MatSize(unsigned int first=0, unsigned int second=0);   //C'tor
    //MatSize(unsigned int sz); //C'tor for square matrix
    MatSize operator*(const MatSize& other) const;          //The size of the matrix get by multiply the 2 matrices
    MatSize operator*=(const MatSize& other);
    MatSize transpose();
    MatSize getTransposed() const;
    
    bool operator==(const MatSize& other) const;            //Is these 2 matrices have the same sizes?
    bool operator!=(const MatSize& other) const;
    bool canMultiply(const MatSize& other) const;           //Can we multiply these 2 matrices?
    bool canAdd(const MatSize& other) const;                //Can we add these 2 matrices (Actually same as operator==
    bool isSquare() const;                                  //Is it a square matrix
    void print() const;
    unsigned int size() const;                           //Returns the number of elements in the matrix
};

class PTMatrix;
class EncryptedMatrix;

/*This class represents a plain text matrix, basic operations and decrypting that matrix
 It based on Shai Halevi's article "Algorithms in HElib" and the matrix representation types*/
class PTMatrix{
private:
    vector<vector<long> > matrix;
    
    unsigned int size() const;  //returns matrix.size(). Again, not really useful, uses for some inner operations
    vector<long>& operator[](unsigned int i); //returns the i-th vector. Not really useful, uses for some inner operations
    const vector<long>& operator[](unsigned int i) const;
public:
    //C'tors
    PTMatrix(vector<vector<long> > _matrix, bool diagonal=true);
    PTMatrix(MatSize sizes, unsigned int numbersLimit = 10);   //random matrix
    PTMatrix(ifstream& file); //read the matrix from a file
    
    //Encrypting
    EncryptedMatrix encrypt(const EncryptedArray& ea, const FHEPubKey& publicKey) const;
    EncryptedMatrix encrypt(const FHEPubKey& publicKey) const;
    
    PTMatrix getSubMatrix(unsigned int i, unsigned int j, MatSize size) const; //get a sub matrix starts at [i,j] and it size is "size". Uses for the grid classes
    
    unsigned int getRows() const;       //returns number of rows in the matrix
    unsigned int getColumns() const;    //returns number of columns in the matrix
    MatSize getMatrixSize() const;      //returns the size of the matrix as MatSize object
    vector<vector<long> > getMatrix() const;    //return the matrix as rows order matrix
    
    void print(string label="") const;   //prints the matrix with some comment/label
    bool save(ofstream& file) const;
    
    //operators:
    //NOTE: the idea of Homomorphic Encryption is to do these operations on encrypted data, so using these operation is useless. It uses for statistics, for checking how slower are some operations on the encrypted data compared to the operations in the plain text data
    
    //matrices multiplication
    PTMatrix operator*(const PTMatrix& other) const;
    PTMatrix operator*=(const PTMatrix& other);
    
    //Mul by constant
    PTMatrix operator*(unsigned int num) const;
    PTMatrix operator*=(unsigned int num);
    
    //matrices addition
    PTMatrix operator+(const PTMatrix& other) const;
    PTMatrix operator+=(const PTMatrix& other);
    
    //matrices substruction
    PTMatrix operator-(const PTMatrix& other) const;
    PTMatrix operator-=(const PTMatrix& other);
    
    //Transpose
    PTMatrix transpose() const;
    
    PTMatrix operator>(const PTMatrix& other) const;
    PTMatrix operator<(const PTMatrix& other) const;
    PTMatrix operator>=(const PTMatrix& other) const;
    PTMatrix operator<=(const PTMatrix& other) const;
    
    bool operator==(const PTMatrix& other) const;
    bool operator!=(const PTMatrix& other) const;
    
    //operator%, apply %p on each element in the matrix. Use for checking if the encrypted multiplication's result is right, because it calculated under some modulo field
    PTMatrix operator%(unsigned int p) const;
    PTMatrix operator%=(unsigned int p);
    
    long& operator()(unsigned int row, unsigned int column); //return the element in [i,j] if it was regular matrix
    const long& operator()(unsigned int row, unsigned int column) const;
    
    //for debug
    PTMatrix mulWithMod(const PTMatrix& other, long p) const; //same as operator* but do mod after each mult to avoid overflow as possible
    void debugPrintDiagonalMatrixVector();
};

//This class represents an encrypted matrix.
class EncryptedMatrix{
private:
    vector<Ctxt> matrix;
    MatSize matrixSize; //help to keep the plainText matrix size before it were resized to be encrypted
    
    Ctxt& operator[](unsigned int i);  //returns the i-th Ctxt. Not really useful, uses for some inner operations
    const Ctxt& operator[](unsigned int i) const;
public:
    EncryptedMatrix(const vector<Ctxt>& encMatrix, const MatSize& origSize);  //C'tor
    
    //Decrypt
    PTMatrix decrypt(const EncryptedArray& ea, const FHESecKey& secretKey) const;
    PTMatrix decrypt(const FHESecKey& secretKey) const;
    
    //matrices multiplication
    EncryptedMatrix operator*(const EncryptedMatrix& other) const;
    EncryptedMatrix operator*=(const EncryptedMatrix& other);
    
    //mult by constant
    EncryptedMatrix operator*(unsigned int num) const;
    EncryptedMatrix operator*=(unsigned int num);
    
    //matrices addition
    EncryptedMatrix operator+(const EncryptedMatrix& other) const;
    EncryptedMatrix operator+=(const EncryptedMatrix& other);
    
    //matrices substruction (STILL NOT WORKING)
    EncryptedMatrix operator-(const EncryptedMatrix& other) const;
    EncryptedMatrix operator-=(const EncryptedMatrix& other);
    
    //Transpose
    EncryptedMatrix transpose() const;
    
    //the comparing operators (<, >, <= and >=) WORKING ONLY FOR BINARY FIELDS (P=2)
    EncryptedMatrix operator>(const EncryptedMatrix& other) const;
    EncryptedMatrix operator<(const EncryptedMatrix& other) const;
    EncryptedMatrix operator>=(const EncryptedMatrix& other) const;
    EncryptedMatrix operator<=(const EncryptedMatrix& other) const;
    
    //Comparison, based on HElib's Ctxt:operator==
    bool operator==(const EncryptedMatrix& other) const;
    bool operator!=(const EncryptedMatrix& other) const;
    
    //matrix multyplication by vector
    Ctxt operator*(const Ctxt& vec) const;
    
    unsigned int getRows() const;                   //returns number of rows
    unsigned int getColumns() const;                //returns the number of columns
    MatSize getMatrixSize() const;                  //returns the matrix size as MatSize object
    
    //debug operators
    EncryptedMatrix debugMul(const EncryptedMatrix& other, bool logFile = true, bool relinearation = false) const;
    EncryptedMatrix debugAdd(const EncryptedMatrix& other, bool logFile = true) const;
};

//EXCEPTIONS
class MatricesSizesNotMatch:public runtime_error{
public:
    MatricesSizesNotMatch(const MatSize& m1, const MatSize& m2) : runtime_error("Matrices sizes are not match!"), sz1(m1), sz2(m2) {}
    const char* what(){
        cnvt.str( "" );
        cnvt << runtime_error::what() << ": First matrix size: " << sz1.rows << "x" << sz1.columns << ", second matrix size: " << sz2.rows << "x" << sz2.columns;
        return cnvt.str().c_str();
    }
    ~MatricesSizesNotMatch() throw() {};
private:
    MatSize sz1, sz2;
    static ostringstream cnvt;
};

class NotBinaryField:public runtime_error{
public:
    NotBinaryField(): runtime_error("For this operation, the plain text space MUST be binary!") {};
    const char* what(){ return runtime_error::what(); }
    ~NotBinaryField() throw() {};
};