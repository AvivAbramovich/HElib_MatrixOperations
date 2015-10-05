#include "Matrices.h"
#include <sys/time.h>

using namespace std;

int main(){
    //create a random matrix and save it in a file
    PTMatrix mat1(MatSize(5,3), 100);
    ofstream outputFile("test_file.txt");
    mat1.print();
    mat1.save(outputFile);
    outputFile.close();
    
    //open a matrix from a file
    ifstream inFile("test_file.txt");
    PTMatrix mat2(inFile);
    inFile.close();
    mat2.print();
    
    //change the matrix
    mat2(0,0) = 500;
    mat2.print();
    
    //save it back to the file
    ofstream outFile("test_file.txt");
    mat2.save(outFile);
    outFile.close();
    return 0;
}