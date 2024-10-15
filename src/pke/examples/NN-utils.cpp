//
// Created by Şeyda Nur Güzelhan on 9/6/24.
//
#include "NN-utils.h"

Ctxt ENN::relu(Ctxt ct, int degree){

    auto cc = ct->GetCryptoContext();

    double lowerBound = -0.4;
    double upperBound = 0.4;

    return cc->EvalLogistic(ct, lowerBound, upperBound, degree);
};

Ctxt ENN::initialLayer(Ctxt ct){
    auto cc = ct->GetCryptoContext();

    auto result = cc->EvalMult(ct, cc->EvalRotate(ct, 1));

    return result;
};


Ctxt ENN::finalLayer(Ctxt ct){
    auto cc = ct->GetCryptoContext();

    auto result = ct;

    return result;
};

vector<double> ENN::read_values_from_file(string filename){

    vector<double> values;
    ifstream file(filename);

    if (!file.is_open()) {
        std::cerr << "Can not open " << filename << std::endl;
    }

    string row;
    while (getline(file, row)) {
        istringstream stream(row);
        string value;
        while (std::getline(stream, value, ',')) {
            values.push_back(stod(value));
        }
    }

    file.close();
    return values;
}


vector<Ctxt> ENN::conv1(Ctxt ct, int channels){

    // convolution parameters //
    int image_width = 32;
    int image_height = 32;

    int kernel_width = 3;
    int kernel_height = 3;
    ////////////////////////////

    int size = kernel_width*kernel_height;
    int padding_width = kernel_width - 1;
    int padding_height = kernel_height - 1;
//    int padded_size = image_width*image_height + 2*padding_height*image_width + 2*padding_width*image_height + 4;
    int padded_size = image_width*image_height;

    auto cc = ct->GetCryptoContext();
    auto keys = cc->KeyGen();

    vector<Ctxt> conved_channels;

    for (int i = 0; i < channels; i++) {
        vector<double> weight_values = read_values_from_file("weights/conv1-ch" + to_string(i) + "-k.bin");
        Ctxt weights                 = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(weight_values));
        vector<double> values        = read_values_from_file("weights/conv1-ch" + to_string(i) + "-bias.bin");
        Ctxt bias                    = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(values));

        Ctxt conv_image_result = ct->Clone();
        auto cv = conv_image_result->GetElements();

        for(int j=0; j<padded_size; j++) {
            Ctxt ctRot = cc->EvalRotate(ct, j); // to do: padded image ciphertext?
            conv_image_result = cc->EvalAdd(conv_image_result, ENN::conv3x3(ctRot, weights, bias, size)); // to do: write this value to the correct location
        }
        conved_channels.push_back(conv_image_result);
    }

    return conved_channels;
}

Ctxt ENN::conv3x3(Ctxt ct, Ctxt weights, Ctxt bias, int size) {

    auto cc = ct->GetCryptoContext();

    Ctxt cMult = cc->EvalMult(ct, weights);
    auto cMultPrecomp = cc->EvalFastRotationPrecompute(cMult);
    Ctxt cAdd = cMult->Clone();
    for (int i=0; i<size; i++) {
        cAdd = cc->EvalAdd(cAdd, cc->EvalFastRotation(cMult, i, cc->GetCyclotomicOrder(), cMultPrecomp));
    }
    cAdd = cc->EvalAdd(cAdd, bias);

    return cAdd;
}


vector<double> ENN::read_image(const char *filename, int width, int height, int channels) {

    unsigned char* image_data = stbi_load(filename, &width, &height, &channels, 0);

    if (!image_data) {
        cerr << "Could not load the image in " << filename << endl;
        return vector<double>();
    }

    vector<double> imageVector;
    imageVector.reserve(width * height * channels);

    for (int i = 0; i < width * height; ++i) {
        //Channel R
        imageVector.push_back(static_cast<double>(image_data[3 * i]) / 255.0f);
    }
    for (int i = 0; i < width * height; ++i) {
        //Channel G
        imageVector.push_back(static_cast<double>(image_data[1 + 3 * i]) / 255.0f);
    }
    for (int i = 0; i < width * height; ++i) {
        //Channel B
        imageVector.push_back(static_cast<double>(image_data[2 + 3 * i]) / 255.0f);
    }

    stbi_image_free(image_data);

    return imageVector;
}


