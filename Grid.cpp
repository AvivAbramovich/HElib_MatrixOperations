//  Created by Aviv Abramovich on 4/08/15.
//  Copyright (c) 2015 Aviv Abramovich. All rights reserved.

#include "Grid.h"

bool isPowerOf2(unsigned int num){
    if( num == 1)
        return true;
    return num%2 ? false : isPowerOf2(num/2);
}

EncryptedMatrixGrid StrassenMultiplication(const EncryptedMatrixGrid& grid1, const EncryptedMatrixGrid& grid2)
/*Strassen algorithm for matrices multiplication. Work ONLY on square grids at size 2^n (power on 2). Complixety is O(n^2.8074) instead O(n^3)
Strassen algorithm:
 grid1 is [a11, a12 ; a21, a22], grid2 is [b11, b12 ; b21, b22], result is C: [C11 , C12 ; C21, C22]
 G1 = (a11 + a22)*(b11+b22)
 G2 = (a21 + a22)*b11
 G3 = a11*(b12 - b22)
 G4 = a22*(b21 - b11)
 G5 = (a11 + a12)*b22
 G6 = (a21 - a11)*(b11 + b12)
 G7 = (a12 - a22)*(b21 + b22)
 
 C11 = G1 + G4 - G5 + G7
 C12 = G3 + G5
 C21 = G2 + G4
 C22 = G1 - G2 +G3 + G6
 */
{
    unsigned int len = grid1.size();
    unsigned int quartLen = len/4;
    EncryptedMatrixGrid a11 = grid1.getSubGrid(0,0, quartLen, quartLen), a12 = grid1.getSubGrid(quartLen,0, quartLen, quartLen),
                        a21 = grid1.getSubGrid(0,quartLen, quartLen, quartLen), a22 = grid1.getSubGrid(quartLen,quartLen, quartLen, quartLen),
                        b11 = grid2.getSubGrid(0,0, quartLen, quartLen), b12 = grid2.getSubGrid(quartLen,0, quartLen, quartLen),
                        b21 = grid2.getSubGrid(0,quartLen, quartLen, quartLen), b22 = grid2.getSubGrid(quartLen,quartLen, quartLen, quartLen);
    EncryptedMatrixGrid G1 = (a11 + a22)*(b11+b22);
    EncryptedMatrixGrid G2 = (a21 + a22)*b11;
    EncryptedMatrixGrid G3 = a11*(b12 - b22);
    EncryptedMatrixGrid G4 = a22*(b21 - b11);
    EncryptedMatrixGrid G5 = (a11 + a12)*b22;
    EncryptedMatrixGrid G6 = (a21 - a11)*(b11 + b12);
    EncryptedMatrixGrid G7 = (a12 - a22)*(b21 + b22);
    
    EncryptedMatrixGrid C11 = G1+G4-G5+G7;
    EncryptedMatrixGrid C12 = G3+G5;
    EncryptedMatrixGrid C21 = G2+G4;
    EncryptedMatrixGrid C22 = G1-G2+G3+G6;

    C11.concat(C12); C21.concat(C22);
    C11.push(C21);
    return C11;
}

/* ------------------------------- PTMatrixGrid --------------------------------------*/
PTMatrixGrid::PTMatrixGrid(const PTMatrix& matrix, const MatSize blockSize){
    unsigned int numRows = 0, numCols = 0;
    MatSize origSize = matrix.getMatrixSize();
    numRows = origSize.rows/blockSize.rows;   numCols = origSize.columns/blockSize.columns;
    if(origSize.rows % blockSize.rows != 0){
        cout << "The number of rows in the wanted size (" << blockSize.rows <<") is not divide the matrix size (" << origSize.rows <<")"<<endl;
        numRows++;  //for the "שארית"
    }
    if(origSize.columns % blockSize.columns != 0){
        cout << "The number of columns in the wanted size (" << blockSize.columns <<") is not divide the matrix size (" << origSize.columns <<")"<<endl;
        numCols++;  //for the "שארית"
    }
    grid = vector<vector<PTMatrix> >(numRows);
    for(unsigned int i=0; i< numRows; i++)
        for(unsigned int j=0; j< numCols; j++)
            grid[i].push_back(matrix.getSubMatrix(i*blockSize.rows, j*blockSize.columns, blockSize));
}

PTMatrixGrid::PTMatrixGrid(const vector<vector<PTMatrix> >& matrixGrid) : grid(matrixGrid) {}

EncryptedMatrixGrid PTMatrixGrid::encrypt(const EncryptedArray& ea, const FHEPubKey& publicKey) const{
    vector<vector<EncryptedMatrix> > mat(grid.size());
    for(unsigned int i=0; i < grid.size(); i++)
        for(unsigned int j=0; j< grid[0].size(); j++)
            mat[i].push_back(grid[i][j].encrypt(ea, publicKey));
    return EncryptedMatrixGrid(mat);
}

EncryptedMatrixGrid PTMatrixGrid::encrypt(const FHEPubKey& publicKey) const{
    EncryptedArray ea(publicKey.getContext());
    return encrypt(ea, publicKey);
}

PTMatrix PTMatrixGrid::reunion() const {
    vector<vector<long> >mat(getRows());
    unsigned int rowsInBlock = grid[0][0].getRows();
    for(unsigned int i=0, sz1 = grid.size(); i< sz1; i++)
        for(unsigned int j=0, sz2 = grid[i].size(); j< sz2; j++)
            for(unsigned int k=0, sz3 = grid[i][j].getRows(); k< sz3; k++)
                for(unsigned int l=0, sz4 = grid[i][j].getColumns(); l < sz4; l++)
                    mat[i*rowsInBlock+k].push_back((*this)[i][j](k,l));
    return PTMatrix(mat, false);
}

//in getRows and getColumns, multiply the number of blocks in rows/columns with the size of the first block,
//except the last block, that calculated seperatly because it may be smaller than the other
unsigned int PTMatrixGrid::getRows() const{ return grid[0][0].getRows()*(grid.size()-1)+grid[grid.size()-1][0].getRows(); }

unsigned int PTMatrixGrid::getColumns() const{ return grid[0][0].getColumns()*(grid[0].size()-1)+grid[0][grid.size()-1].getColumns(); }

vector<PTMatrix> PTMatrixGrid::operator[](unsigned int i) const {  return grid[i]; }

MatSize PTMatrixGrid::getGridSize() const { return MatSize(grid.size(), grid[0].size()); }

MatSize PTMatrixGrid::getMatrixSize() const { return MatSize(getRows(), getColumns()); }

unsigned int PTMatrixGrid::size() const { return grid.size(); }

bool PTMatrixGrid::concat(const PTMatrixGrid& other){
    if(grid.size() != other.grid.size() || grid[0][0].getMatrixSize() != other[0][0].getMatrixSize())
        return false;
    for(unsigned int i=0; i < grid.size(); i++)
        grid[i].insert(grid[i].end(), other[i].begin(), other[i].end());
    return true;
}
bool PTMatrixGrid::push(const PTMatrixGrid& other){
    if(grid[0].size() != other[0].size() || grid[0][0].getMatrixSize() != other[0][0].getMatrixSize())
        return false;
    for(unsigned int i=0; i < other.grid.size(); i++)
        grid.push_back(other[i]);
    return true;
}

/* ------------------------------- PTVectorGrid --------------------------------------*/
PTVectorGrid::PTVectorGrid(const vector<long>& vec, unsigned int size){
    grid = vector<vector<long> >(vec.size()/size, vector<long>(size));
    for(unsigned int i=0; i < grid.size(); i++)
        for(unsigned int j=0; j< grid[i].size(); j++)
            grid[i][j] = vec[i*size+j];
    
    if(vec.size() % size !=0){
        cout << "The wnated size of each sub-vector (" << size << ") is not divide the vector length (" << vec.size() << ")" << endl;
        //adding the ״שארית״
        unsigned int totalSize = size*grid.size();
        vector<long> sheerit;
        for(unsigned int i=totalSize; i< vec.size(); i++)
            sheerit.push_back(vec[i]);
        grid.push_back(sheerit);
    }
}

PTVectorGrid::PTVectorGrid(const vector<vector<long> >& gridVec): grid(gridVec) {}

EncryptedVectorGrid PTVectorGrid::encrypt(const EncryptedArray& ea, const FHEPubKey& publicKey) const{
    vector<Ctxt> enc;
    unsigned int nslots = ea.size();
    for(unsigned int i=0; i< grid.size(); i++){
        vector<long> temp = grid[i];
        Ctxt encTemp(publicKey);
        if(temp.size() < nslots)
            temp.resize(nslots, 0);
        ea.encrypt(encTemp, publicKey, temp);
        enc.push_back(encTemp);
    }
    return EncryptedVectorGrid(enc);
}

EncryptedVectorGrid PTVectorGrid::encrypt(const FHEPubKey& publicKey) const{
    EncryptedArray ea(publicKey.getContext());
    return encrypt(ea, publicKey);
}

vector<long> PTVectorGrid::reunion() const {
    vector<long> result;
    for(unsigned int i=0; i< grid.size(); i++)
        for(unsigned int j=0; j < grid[i].size(); j++)
            result.push_back(grid[i][j]);
    return result;
}

vector<long> PTVectorGrid::operator[](unsigned int i) const {  return grid[i]; }

MatSize PTVectorGrid::getVectorSize() const {
    unsigned int len = 0, sz = grid.size();
    for(unsigned int i=0; i < sz; i++)
        len += grid[i].size();
    return MatSize(len, 1);
}

/* ------------------------------- EncryptedMatrixGrid -------------------------------*/
EncryptedMatrixGrid::EncryptedMatrixGrid(const vector<vector<EncryptedMatrix> >& matrix): grid(matrix), StrassenEnabled(false), StrassenLimit(0) {}

PTMatrixGrid EncryptedMatrixGrid::decrypt(const EncryptedArray& ea, const FHESecKey& secretKey) const{
    vector<vector<PTMatrix> > result(grid.size());
    for(unsigned int i=0; i< grid.size(); i++)
        for(unsigned int j=0; j < grid[i].size(); j++)
            result[i].push_back(grid[i][j].decrypt(ea, secretKey));
    return PTMatrixGrid(result);
}

PTMatrixGrid EncryptedMatrixGrid::decrypt(const FHESecKey& secretKey) const{
    EncryptedArray ea(secretKey.getContext());
    return decrypt(ea, secretKey);
}

EncryptedVectorGrid EncryptedMatrixGrid::operator*(const EncryptedVectorGrid& vec) const{
    if(!getGridSize().canMultiply(vec.size())){
        cout << "ERROR! Sizes  not acceptable! return the Encrypted vector grid" << endl;
        return vec;
    }
    vector<Ctxt> result;
    if(grid[0].size() != vec.size()){
        cout << "ERROR! matrix and vector sizes not acceptable!" << endl;
        return EncryptedVectorGrid(result);    //return an empty vector
    }
    for(unsigned int i=0; i< grid.size(); i++){
        Ctxt temp(vec[0].getPubKey());
        for(unsigned int j=0; j< grid[i].size(); j++)
            temp += grid[i][j]*vec[j];
        result.push_back(temp);
    }
    return EncryptedVectorGrid(result);
}

EncryptedMatrixGrid EncryptedMatrixGrid::operator*(const EncryptedMatrixGrid& other) const{
    //Check if sizes are ok
    if(!getGridSize().canMultiply(other.getGridSize()) || !grid[0][0].getMatrixSize().canMultiply(other[0][0].getMatrixSize())){
        cout << "Grids sizes not compatible. return the first grid" << endl;
        return *this;
    }
    //Check if can use Strassen algorithm
    if(StrassenEnabled && grid.size() == grid[0].size() && other.size() == other[0].size() &&  isPowerOf2(grid.size()) && grid.size() > StrassenLimit)
        return StrassenMultiplication(*this, other);
    
    vector<vector<EncryptedMatrix> > result(grid.size());
    for(unsigned int i=0; i< size(); i++)
        for(unsigned int j=0; j < other[0].size(); j++){
            EncryptedMatrix temp = grid[i][0]*other[0][j];
            for(unsigned int k=1; k < grid[i].size(); k++){
                temp += grid[i][k]*other[k][j];
            }
            result[i].push_back(temp);
        }
    return EncryptedMatrixGrid(result);
}

EncryptedMatrixGrid EncryptedMatrixGrid::operator*=(const EncryptedMatrixGrid& other){ return ((*this) = (*this)*other); }

EncryptedMatrixGrid EncryptedMatrixGrid::operator+(const EncryptedMatrixGrid& other) const{
    if(getGridSize()!=other.getGridSize() || grid[0][0].getMatrixSize()!=other[0][0].getMatrixSize()){
        cout << "Grids sizes not compatible. return the first grid" << endl;
        return *this;
    }
    vector<vector<EncryptedMatrix> > result(grid.size());
    for(unsigned int i=0; i< size(); i++)
        for(unsigned int j=0; j < other[0].size(); j++)
            result[i].push_back(grid[i][j]+other[i][j]);
    return EncryptedMatrixGrid(result);
}

EncryptedMatrixGrid EncryptedMatrixGrid::operator+=(const EncryptedMatrixGrid& other){ return ((*this) = (*this)+other); }

EncryptedMatrixGrid EncryptedMatrixGrid::operator-(const EncryptedMatrixGrid& other) const{
    if(getGridSize()!=other.getGridSize() || grid[0][0].getMatrixSize()!=other[0][0].getMatrixSize()){
        cout << "Grids sizes not compatible. return the first grid" << endl;
        return *this;
    }
    vector<vector<EncryptedMatrix> > result(grid.size());
    for(unsigned int i=0; i< size(); i++)
        for(unsigned int j=0; j < other[0].size(); j++)
            result[i].push_back(grid[i][j]-other[i][j]);
    return EncryptedMatrixGrid(result);
}

EncryptedMatrixGrid EncryptedMatrixGrid::operator-=(const EncryptedMatrixGrid& other){ return ((*this) = (*this)-other); }

bool EncryptedMatrixGrid::operator==(const EncryptedMatrixGrid& other) const {
    if(getGridSize() != other.getGridSize() || grid[0][0].getMatrixSize() != other[0][0].getMatrixSize())
        return false;
    MatSize sz = getGridSize();
    for(unsigned int i=0; i < sz.rows; i++)
        for(unsigned int j=0; j < sz.columns; j++)
            if(grid[i][j] != other[i][j])
                return false;
    return true;
}

bool EncryptedMatrixGrid::operator!=(const EncryptedMatrixGrid& other) const { return !(*this == other); }

MatSize EncryptedMatrixGrid::getGridSize() const { return MatSize(grid.size(), grid[0].size()); }

vector<EncryptedMatrix> EncryptedMatrixGrid::operator[](unsigned int i) const { return grid[i]; }

EncryptedMatrixGrid EncryptedMatrixGrid::getSubGrid(unsigned int firstRow, unsigned int firstColumn, unsigned int numRows, unsigned int numColumns) const{
    unsigned int len = numRows > grid.size() - firstRow ? grid.size() - firstRow : numRows;
    vector<vector<EncryptedMatrix> > res(len);
    for(unsigned int i=0; i < numRows && i+firstRow < grid.size(); i++)
        for(unsigned int j=0 ; j < numColumns && j+firstColumn < grid[i].size(); j++)
            res[i].push_back(grid[i+firstRow][j+firstColumn]);
    return EncryptedMatrixGrid(res);
}

bool EncryptedMatrixGrid::concat(const EncryptedMatrixGrid& other){
    if(grid.size() != other.size() || grid[0][0].getMatrixSize() != other[0][0].getMatrixSize())
        return false;
    for(unsigned int i=0; i < grid.size(); i++)
        grid[i].insert(grid[i].end(), other[i].begin(), other[i].end());
    return true;
}
bool EncryptedMatrixGrid::push(const EncryptedMatrixGrid& other){
    if(grid[0].size() != other[0].size() || grid[0][0].getMatrixSize() != other[0][0].getMatrixSize())
        return false;
    for(unsigned int i=0; i < other.size(); i++)
        grid.push_back(other[i]);
    return true;
}

unsigned int EncryptedMatrixGrid::size() const { return grid.size(); }

//enable/disable Strassen
void EncryptedMatrixGrid::enableStrassenMultiplication(unsigned int limit){
    StrassenEnabled = true;
    StrassenLimit = limit;
}
void EncryptedMatrixGrid::disableStrassenMultiplication(){ StrassenEnabled = false; }

bool EncryptedMatrixGrid::isStrassenEnabled() const { return StrassenEnabled; }

unsigned int EncryptedMatrixGrid::getStrassenLimit() const { return StrassenLimit; }

/* ------------------------------- EncryptedVectorGrid -------------------------------*/
EncryptedVectorGrid::EncryptedVectorGrid(vector<Ctxt>& vec): grid(vec) {}

PTVectorGrid EncryptedVectorGrid::decrypt(const EncryptedArray& ea, const FHESecKey& secretKey) const{
    vector<vector<long> > vec;
    for(unsigned int i=0; i< grid.size(); i++){
        vector<long> temp;
        ea.decrypt(grid[i], secretKey, temp);
        vec.push_back(temp);
    }
    return PTVectorGrid(vec);
}

PTVectorGrid EncryptedVectorGrid::decrypt(const FHESecKey& secretKey) const{
    EncryptedArray ea(secretKey.getContext());
    return decrypt(ea, secretKey);
}

unsigned int EncryptedVectorGrid::size() const{ return grid.size(); }

Ctxt EncryptedVectorGrid::operator[](unsigned int i) const { return grid[i]; }