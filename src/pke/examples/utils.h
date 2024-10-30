//
// Created by Şeyda Nur Güzelhan on 9/6/24.
//

#ifndef OPENFHE_UTILS_H

#include <iostream>
#include <vector>
#include <cmath>

using namespace std;

void compare_vectors(vector<double> v1, vector<double> v2, int size, double precision){

    int flag = 1;
    for(int i=0; i<size; i++){
        if ((v1[i] - v2[i]) > precision) {
            flag = 0;
        };
    };
    if (flag){
        cout << "Vectors are the same!" << endl;
        }
        else {
            cout << "Vectors are different!" << endl;

        };
};

#define OPENFHE_UTILS_H

#endif  //OPENFHE_UTILS_H
