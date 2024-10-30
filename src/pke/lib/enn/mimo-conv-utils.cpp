//
// Created by Şeyda Nur Güzelhan on 9/6/24.
//
#include "enn/mimo-conv-utils.h"

vector<vector<vector<Ctxt>>> ENN::pack_images_mimo(CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keys, vector<vector<double>> x_s, int cn, int f, int iw, int ih, int padding) {

    int ci = x_s.size();
    int ci_cn = ceil(ci / cn);
    vector<vector<double>> x_inputs(ci_cn);
    for (int i=0; i<ci_cn; i++){
        for (int j=0; j<min(cn, ci); j++){
            x_inputs[i].insert(x_inputs[i].end(), x_s[i*cn+j].begin(), x_s[i*cn+j].end());
        }
    }

    vector<Ctxt> ct_inputs;
    for (int i=0; i<ci_cn; i++){
        Ptxt temp = cc->MakeCKKSPackedPlaintext(x_inputs[i]);
        ct_inputs.push_back(cc->Encrypt(keys.publicKey, temp));
    }

    vector<vector<vector<Ctxt>>> c_rotations(ci_cn, vector<vector<Ctxt>>(min(cn,ci), vector<Ctxt>(f*f)));

    vector<int> rot_index = {-padding-iw, -iw, +padding-iw, -padding, 0, +padding, -padding+iw, iw, +padding+iw, iw*ih};
    cc->EvalRotateKeyGen(keys.secretKey, rot_index);

    if (f==3) {
        for (int i = 0; i < ci_cn; i++) {
            for (int j = 0; j < min(cn, ci); j++) {
                for (int k = 0; k < f * f; k++) {
//                    c_rotations[i][j][k] = Automorph(ct_inputs[i], rot_index[k]);
                    c_rotations[i][j][k] = cc->EvalRotate(ct_inputs[i], rot_index[k]);
                }
//                ct_inputs[i] = Automorph(ct_inputs[i], ih * iw);
                ct_inputs[i] = cc->EvalRotate(ct_inputs[i], ih * iw);
            }
        }
    }
    else if(f == 5){
        // complete
    }
    return c_rotations;
}

vector<Ctxt> ENN::conv2d_mimo(vector<vector<vector<double>>> weight_list, vector<vector<vector<Ctxt>>> c_rotations, KeyPair<DCRTPoly> keys, int f) {

    int co_cn = weight_list.size();
    int ci_cn = c_rotations.size();
    auto cc = c_rotations[0][0][0]->GetCryptoContext();
    auto algo = cc->GetScheme();




    vector<Ctxt> inter_out_ct(co_cn);

    vector<int> rotIndex = {-5,-4,-3,-1,0,1,3,4,5};
    vector<PrivateKey<DCRTPoly>> secret_keys(f*f);
    for (int i=0; i<f*f; i++){
        secret_keys[i] = Automorph_poly(c_rotations[0][0][0], keys.secretKey, rotIndex[i]);
    }

    for (int j = 0; j < co_cn; j++) {
        vector<Ctxt> inter_in_ct;
        for (int h = 0; h < c_rotations[0].size(); h++) {
            for (int l = 0; l < ci_cn; l++) {
                vector<Ctxt> conv_ct;
                for (int k = 0; k < f * f; k++) {
                    Ptxt weight_pt = cc->MakeCKKSPackedPlaintext(weight_list[j][k]);
                    Ctxt weight = cc->Encrypt(keys.secretKey,weight_pt);
//                    Ctxt weight = cc->Encrypt(secret_keys[k],weight_pt);

//                    uint32_t autoIndex = FindAutomorphismIndex2nComplex(rotIndex[k], cc->GetCyclotomicOrder());  //
//                    auto evalKeyMap = CryptoContextImpl<DCRTPolyImpl<mubintvec<ubint<unsigned long long>>>>::GetEvalAutomorphismKeyMap(c_rotations[0][0][0]->GetKeyTag());
//                    auto evalKeyIterator = evalKeyMap.find(autoIndex);

//                    algo->KeySwitchInPlace(weight, evalKeyIterator->second);
//                    algo->KeySwitchInPlace(c_rotations[l][h][k], evalKeyIterator->second);

                    Ctxt cMult     = cc->EvalMult(weight, c_rotations[l][h][k]);

                    conv_ct.push_back(cMult);
                }
                Ctxt inter_conv_sum = cc->EvalAddMany(conv_ct);
                inter_in_ct.push_back(inter_conv_sum);
            }
        }
        Ctxt inter_out_sum = cc->EvalAddMany(inter_in_ct);
        inter_out_ct[j]    = inter_out_sum;
    }

    return inter_out_ct;
}

vector<vector<vector<Ctxt>>> ENN::pack_images_mimo_pt(CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keys, vector<vector<double>> x_s, int cn, int f, int iw, int ih, int padding) {

    int ci = x_s.size();
    int ci_cn = ceil(ci / cn);
    vector<vector<double>> x_inputs(ci_cn);
    for (int i=0; i<ci_cn; i++){
        for (int j=0; j<min(cn, ci); j++){
            x_inputs[i].insert(x_inputs[i].end(), x_s[i*cn+j].begin(), x_s[i*cn+j].end());
        }
    }

    vector<Ctxt> ct_inputs;
    for (int i=0; i<ci_cn; i++){
        Ptxt temp = cc->MakeCKKSPackedPlaintext(x_inputs[i]);
        ct_inputs.push_back(cc->Encrypt(keys.publicKey, temp));
    }

    vector<vector<vector<Ctxt>>> c_rotations(ci_cn, vector<vector<Ctxt>>(min(cn,ci), vector<Ctxt>(f*f)));

    vector<int> rot_index = {-padding-iw, -iw, +padding-iw, -padding, 0, +padding, -padding+iw, iw, +padding+iw, iw*ih};
    cc->EvalRotateKeyGen(keys.secretKey, rot_index);

    if (f==3) {
        for (int i = 0; i < ci_cn; i++) {
            for (int j = 0; j < min(cn, ci); j++) {
                for (int k = 0; k < f * f; k++) {
                    c_rotations[i][j][k] = cc->EvalRotate(ct_inputs[i], rot_index[k]);
                }
                ct_inputs[i] = cc->EvalRotate(ct_inputs[i], ih * iw);
            }
        }
    }
    else if(f == 5){
        // complete
    }
    return c_rotations;
}

vector<vector<vector<double>>> ENN::pack_weights_mimo(vector<vector<double>> weights, int cn, int f, int img_size) {

    int co = weights.size();
    int co_cn = ceil((double)co / cn);
    vector<vector<vector<double>>> weight_list(co_cn, vector<vector<double>>(f*f));
    if (f==3 && img_size == 16) {
        for (int j = 0; j < co_cn; j++) {
            for (int i = 0; i < min(cn, co); i++) {
                weight_list[j][0].insert(
                    weight_list[j][0].end(),
                    {0, 0, 0, 0, 0, weights[i + j * cn][0], weights[i + j * cn][0], weights[i + j * cn][0], 0,
                     weights[i + j * cn][0], weights[i + j * cn][0], weights[i + j * cn][0], 0, weights[i + j * cn][0],
                     weights[i + j * cn][0], weights[i + j * cn][0]});
                weight_list[j][1].insert(
                    weight_list[j][1].end(),
                    {0, 0, 0, 0, weights[i + j * cn][1], weights[i + j * cn][1], weights[i + j * cn][1],
                     weights[i + j * cn][1], weights[i + j * cn][1], weights[i + j * cn][1], weights[i + j * cn][1],
                     weights[i + j * cn][1], weights[i + j * cn][1], weights[i + j * cn][1], weights[i + j * cn][1],
                     weights[i + j * cn][1]});
                weight_list[j][2].insert(
                    weight_list[j][2].end(),
                    {0, 0, 0, 0, weights[i + j * cn][2], weights[i + j * cn][2], weights[i + j * cn][2], 0,
                     weights[i + j * cn][2], weights[i + j * cn][2], weights[i + j * cn][2], 0, weights[i + j * cn][2],
                     weights[i + j * cn][2], weights[i + j * cn][2], 0});
                weight_list[j][3].insert(weight_list[j][3].end(),
                                         {0, weights[i + j * cn][3], weights[i + j * cn][3], weights[i + j * cn][3], 0,
                                          weights[i + j * cn][3], weights[i + j * cn][3], weights[i + j * cn][3], 0,
                                          weights[i + j * cn][3], weights[i + j * cn][3], weights[i + j * cn][3], 0,
                                          weights[i + j * cn][3], weights[i + j * cn][3], weights[i + j * cn][3]});
                weight_list[j][4].insert(
                    weight_list[j][4].end(),
                    {weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4],
                     weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4],
                     weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4],
                     weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4]});
                weight_list[j][5].insert(weight_list[j][5].end(),
                                         {weights[i + j * cn][5], weights[i + j * cn][5], weights[i + j * cn][5], 0,
                                          weights[i + j * cn][5], weights[i + j * cn][5], weights[i + j * cn][5], 0,
                                          weights[i + j * cn][5], weights[i + j * cn][5], weights[i + j * cn][5], 0,
                                          weights[i + j * cn][5], weights[i + j * cn][5], weights[i + j * cn][5], 0});
                weight_list[j][6].insert(
                    weight_list[j][6].end(),
                    {0, weights[i + j * cn][6], weights[i + j * cn][6], weights[i + j * cn][6], 0,
                     weights[i + j * cn][6], weights[i + j * cn][6], weights[i + j * cn][6], 0, weights[i + j * cn][6],
                     weights[i + j * cn][6], weights[i + j * cn][6], 0, 0, 0, 0});
                weight_list[j][7].insert(
                    weight_list[j][7].end(),
                    {weights[i + j * cn][7], weights[i + j * cn][7], weights[i + j * cn][7], weights[i + j * cn][7],
                     weights[i + j * cn][7], weights[i + j * cn][7], weights[i + j * cn][7], weights[i + j * cn][7],
                     weights[i + j * cn][7], weights[i + j * cn][7], weights[i + j * cn][7], weights[i + j * cn][7], 0,
                     0, 0, 0});
                weight_list[j][8].insert(
                    weight_list[j][8].end(),
                    {weights[i + j * cn][8], weights[i + j * cn][8], weights[i + j * cn][8], 0, weights[i + j * cn][8],
                     weights[i + j * cn][8], weights[i + j * cn][8], 0, weights[i + j * cn][8], weights[i + j * cn][8],
                     weights[i + j * cn][8], 0, 0, 0, 0, 0});
            }
        }
    }
    else if (f==3 && img_size == 4) {       // Incorrect
        for (int j = 0; j < co_cn; j++) {
            for (int i = 0; i < min(cn, co); i++) {
                weight_list[j][0].insert(weight_list[j][0].end(),{0, 0, 0, weights[i + j * cn][0]});
                weight_list[j][1].insert(weight_list[j][1].end(),{0, 0, weights[i + j * cn][1], weights[i + j * cn][1]});
                weight_list[j][2].insert(weight_list[j][2].end(),{0, 0, weights[i + j * cn][2], 0});
                weight_list[j][3].insert(weight_list[j][3].end(),{0, weights[i + j * cn][3], 0, weights[i + j * cn][3]});
                weight_list[j][4].insert(weight_list[j][4].end(),{weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4]});
                weight_list[j][5].insert(weight_list[j][5].end(),{weights[i + j * cn][5], 0, weights[i + j * cn][5], 0});
                weight_list[j][6].insert(weight_list[j][6].end(),{0, weights[i + j * cn][6], 0, 0});
                weight_list[j][7].insert(weight_list[j][7].end(),{weights[i + j * cn][7], weights[i + j * cn][7], 0, 0});
                weight_list[j][8].insert(weight_list[j][8].end(),{weights[i + j * cn][8], 0, 0, 0});
            }
        }
    }
    else if (f == 5){
        // complete
    }

    return weight_list;
}

vector<Ctxt> ENN::conv2d_mimo_pt(vector<vector<vector<double>>> weight_list, vector<vector<vector<Ctxt>>> c_rotations, int f) {

    int co_cn = weight_list.size();
    int ci_cn = c_rotations.size();
    auto cc = c_rotations[0][0][0]->GetCryptoContext();
    vector<Ctxt> inter_out_ct(co_cn);
    for (int j = 0; j < co_cn; j++) {
        vector<Ctxt> inter_in_ct;
        for (int h = 0; h < c_rotations[0].size(); h++) {
            for (int l = 0; l < ci_cn; l++) {
                vector<Ctxt> conv_ct;
                for (int k = 0; k < f * f; k++) {
                    Ptxt weight_pt = cc->MakeCKKSPackedPlaintext(weight_list[j][k]);
                    Ctxt cMult     = cc->EvalMult(weight_pt, c_rotations[l][h][k]);
                    conv_ct.push_back(cMult);
                }
                Ctxt inter_conv_sum = cc->EvalAddMany(conv_ct);
                inter_in_ct.push_back(inter_conv_sum);
            }
        }
        Ctxt inter_out_sum = cc->EvalAddMany(inter_in_ct);
        inter_out_ct[j]    = inter_out_sum;
    }

    return inter_out_ct;
}

Ctxt ENN::Automorph(Ctxt ct1, int i){
    auto evalKeyMap = CryptoContextImpl<DCRTPolyImpl<mubintvec<ubint<unsigned long long>>>>::GetEvalAutomorphismKeyMap(ct1->GetKeyTag());

    usint M = ct1->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();
    uint32_t autoIndex = FindAutomorphismIndex2nComplex(i, M);  //

    auto cv = ct1->GetElements();
    usint N = cv[0].GetRingDimension();
    vector<usint> vec(N);
    PrecomputeAutoMap(N, autoIndex, &vec);

    auto algo = ct1->GetCryptoContext()->GetScheme();
    auto cRot2 = ct1->Clone();

    //    auto evalKeyIterator = evalKeyMap.find(autoIndex);
    //    algo->KeySwitchInPlace(cRot2, evalKeyIterator->second);

    cRot2->GetElements()[0] = cRot2->GetElements()[0].AutomorphismTransform(autoIndex, vec);
    cRot2->GetElements()[1] = cRot2->GetElements()[1].AutomorphismTransform(autoIndex, vec);

    return cRot2;
}

PrivateKey<DCRTPoly> ENN::Automorph_poly(Ctxt ct1, PrivateKey<DCRTPoly> sk, int i){
    auto evalKeyMap = CryptoContextImpl<DCRTPolyImpl<mubintvec<ubint<unsigned long long>>>>::GetEvalAutomorphismKeyMap(ct1->GetKeyTag());

    usint M = ct1->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();
    uint32_t autoIndex = FindAutomorphismIndex2nComplex(i, M);  //

    usint N = M/2;
    vector<usint> vec(N);
    PrecomputeAutoMap(N, autoIndex, &vec);

    sk->GetPrivateElement().AutomorphismTransform(autoIndex, vec);

    return sk;
}

Ctxt ENN::relu(Ctxt ct, int degree){

    auto cc = ct->GetCryptoContext();

    double lowerBound = -0.4;
    double upperBound = 0.4;

    return cc->EvalLogistic(ct, lowerBound, upperBound, degree);
};
