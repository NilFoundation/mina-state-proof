; ModuleID = '/mnt/d/gits/zkllvm/examples/merkle_tree_poseidon.cpp'
source_filename = "/mnt/d/gits/zkllvm/examples/merkle_tree_poseidon.cpp"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "assigner"

%"struct.std::__1::array" = type { [49 x __zkllvm_field_pallas_base] }
%"struct.std::__1::array.0" = type { [16 x __zkllvm_field_pallas_base] }
%"struct.std::__1::array.1" = type { [8 x __zkllvm_field_pallas_base] }
%"struct.std::__1::array.2" = type { [4 x __zkllvm_field_pallas_base] }
%"struct.std::__1::array.3" = type { [2 x __zkllvm_field_pallas_base] }
%"struct.nil::crypto3::hashes::poseidon::process" = type { i8 }

$_ZN3nil7crypto34hashINS0_6hashes8poseidonEEENT_10block_typeES5_S5_ = comdat any

$_ZN3nil7crypto36hashes8poseidon7processclEu26__zkllvm_field_pallas_baseu26__zkllvm_field_pallas_base = comdat any

$_ZN3nil7crypto37algebra6fields17pallas_base_field12modulus_bitsE = comdat any

$_ZN3nil7crypto37algebra6fields17pallas_base_field11number_bitsE = comdat any

$_ZN3nil7crypto37algebra6fields17pallas_base_field10value_bitsE = comdat any

$_ZN3nil7crypto37algebra6fields16vesta_base_field12modulus_bitsE = comdat any

$_ZN3nil7crypto37algebra6fields16vesta_base_field11number_bitsE = comdat any

$_ZN3nil7crypto37algebra6fields16vesta_base_field10value_bitsE = comdat any

@_ZZN3nil7crypto314multiprecision8backends11window_bitsEmE5wsize = internal unnamed_addr constant [6 x [2 x i64]] [[2 x i64] [i64 1434, i64 7], [2 x i64] [i64 539, i64 6], [2 x i64] [i64 197, i64 4], [2 x i64] [i64 70, i64 3], [2 x i64] [i64 17, i64 2], [2 x i64] zeroinitializer], align 8
@_ZN3nil7crypto37algebra6fields17pallas_base_field12modulus_bitsE = weak_odr dso_local local_unnamed_addr constant i64 255, comdat, align 8
@_ZN3nil7crypto37algebra6fields17pallas_base_field11number_bitsE = weak_odr dso_local local_unnamed_addr constant i64 255, comdat, align 8
@_ZN3nil7crypto37algebra6fields17pallas_base_field10value_bitsE = weak_odr dso_local local_unnamed_addr constant i64 255, comdat, align 8
@_ZN3nil7crypto37algebra6fields16vesta_base_field12modulus_bitsE = weak_odr dso_local local_unnamed_addr constant i64 255, comdat, align 8
@_ZN3nil7crypto37algebra6fields16vesta_base_field11number_bitsE = weak_odr dso_local local_unnamed_addr constant i64 255, comdat, align 8
@_ZN3nil7crypto37algebra6fields16vesta_base_field10value_bitsE = weak_odr dso_local local_unnamed_addr constant i64 255, comdat, align 8

; Function Attrs: mustprogress nounwind
define dso_local void @free(i8* noundef %0) local_unnamed_addr #0 {
  tail call void @llvm.assigner.free.p0i8(i8* %0)
  ret void
}

; Function Attrs: nounwind
declare void @llvm.assigner.free.p0i8(i8*) #1

; Function Attrs: mustprogress nounwind allocsize(0)
define dso_local i8* @malloc(i64 noundef %0) local_unnamed_addr #2 {
  %2 = tail call i8* @llvm.assigner.malloc.p0i8(i64 %0)
  ret i8* %2
}

; Function Attrs: nounwind
declare i8* @llvm.assigner.malloc.p0i8(i64) #1

; Function Attrs: mustprogress nounwind
define dso_local noundef i64 @_ZN3nil7crypto314multiprecision8backends11window_bitsEm(i64 noundef %0) local_unnamed_addr #0 {
  br label %2

2:                                                ; preds = %2, %1
  %3 = phi i64 [ 5, %1 ], [ %8, %2 ]
  %4 = getelementptr inbounds [6 x [2 x i64]], [6 x [2 x i64]]* @_ZZN3nil7crypto314multiprecision8backends11window_bitsEmE5wsize, i64 0, i64 %3
  %5 = getelementptr inbounds [2 x i64], [2 x i64]* %4, i64 0, i64 0
  %6 = load i64, i64* %5, align 8, !tbaa !3
  %7 = icmp ugt i64 %6, %0
  %8 = add i64 %3, -1
  br i1 %7, label %2, label %9, !llvm.loop !7

9:                                                ; preds = %2
  %10 = getelementptr inbounds [6 x [2 x i64]], [6 x [2 x i64]]* @_ZZN3nil7crypto314multiprecision8backends11window_bitsEmE5wsize, i64 0, i64 %3
  %11 = getelementptr inbounds [2 x i64], [2 x i64]* %10, i64 0, i64 1
  %12 = load i64, i64* %11, align 8, !tbaa !3
  %13 = add i64 1, %12
  ret i64 %13
}

; Function Attrs: mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #3

; Function Attrs: mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #3

; Function Attrs: circuit mustprogress
define dso_local noundef __zkllvm_field_pallas_base @_Z20merkle_tree_poseidonNSt3__15arrayIu26__zkllvm_field_pallas_baseLm49EEE(%"struct.std::__1::array"* noundef byval(%"struct.std::__1::array") align 1 %0) local_unnamed_addr #4 {
  %2 = alloca %"struct.std::__1::array.0", align 1
  %3 = alloca %"struct.std::__1::array.1", align 1
  %4 = alloca %"struct.std::__1::array.2", align 1
  %5 = alloca %"struct.std::__1::array.3", align 1
  %6 = bitcast %"struct.std::__1::array.0"* %2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 64, i8* %6) #1
  %7 = bitcast %"struct.std::__1::array.1"* %3 to i8*
  call void @llvm.lifetime.start.p0i8(i64 32, i8* %7) #1
  %8 = bitcast %"struct.std::__1::array.2"* %4 to i8*
  call void @llvm.lifetime.start.p0i8(i64 16, i8* %8) #1
  %9 = bitcast %"struct.std::__1::array.3"* %5 to i8*
  call void @llvm.lifetime.start.p0i8(i64 8, i8* %9) #1
  br label %11

10:                                               ; preds = %24
  br label %27

11:                                               ; preds = %1, %24
  %12 = phi i64 [ 0, %1 ], [ %25, %24 ]
  %13 = mul i64 2, %12
  %14 = add i64 14, %13
  %15 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm49EEixEm(%"struct.std::__1::array"* noundef nonnull align 1 dereferenceable(196) %0, i64 noundef %14) #1
  %16 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %15, align 1, !tbaa !10
  %17 = mul i64 2, %12
  %18 = add i64 14, %17
  %19 = add i64 %18, 1
  %20 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm49EEixEm(%"struct.std::__1::array"* noundef nonnull align 1 dereferenceable(196) %0, i64 noundef %19) #1
  %21 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %20, align 1, !tbaa !10
  %22 = call noundef __zkllvm_field_pallas_base @_ZN3nil7crypto34hashINS0_6hashes8poseidonEEENT_10block_typeES5_S5_(__zkllvm_field_pallas_base noundef %16, __zkllvm_field_pallas_base noundef %21)
  %23 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm16EEixEm(%"struct.std::__1::array.0"* noundef nonnull align 1 dereferenceable(64) %2, i64 noundef %12) #1
  store __zkllvm_field_pallas_base %22, __zkllvm_field_pallas_base* %23, align 1, !tbaa !10
  br label %24

24:                                               ; preds = %11
  %25 = add i64 %12, 1
  %26 = icmp ult i64 %25, 16
  br i1 %26, label %11, label %10, !llvm.loop !12

27:                                               ; preds = %10
  br label %29

28:                                               ; preds = %40
  br label %43

29:                                               ; preds = %27, %40
  %30 = phi i64 [ 0, %27 ], [ %41, %40 ]
  %31 = mul i64 2, %30
  %32 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm16EEixEm(%"struct.std::__1::array.0"* noundef nonnull align 1 dereferenceable(64) %2, i64 noundef %31) #1
  %33 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %32, align 1, !tbaa !10
  %34 = mul i64 2, %30
  %35 = add i64 %34, 1
  %36 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm16EEixEm(%"struct.std::__1::array.0"* noundef nonnull align 1 dereferenceable(64) %2, i64 noundef %35) #1
  %37 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %36, align 1, !tbaa !10
  %38 = call noundef __zkllvm_field_pallas_base @_ZN3nil7crypto34hashINS0_6hashes8poseidonEEENT_10block_typeES5_S5_(__zkllvm_field_pallas_base noundef %33, __zkllvm_field_pallas_base noundef %37)
  %39 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm8EEixEm(%"struct.std::__1::array.1"* noundef nonnull align 1 dereferenceable(32) %3, i64 noundef %30) #1
  store __zkllvm_field_pallas_base %38, __zkllvm_field_pallas_base* %39, align 1, !tbaa !10
  br label %40

40:                                               ; preds = %29
  %41 = add i64 %30, 1
  %42 = icmp ult i64 %41, 8
  br i1 %42, label %29, label %28, !llvm.loop !13

43:                                               ; preds = %28
  br label %45

44:                                               ; preds = %56
  br label %59

45:                                               ; preds = %43, %56
  %46 = phi i64 [ 0, %43 ], [ %57, %56 ]
  %47 = mul i64 2, %46
  %48 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm8EEixEm(%"struct.std::__1::array.1"* noundef nonnull align 1 dereferenceable(32) %3, i64 noundef %47) #1
  %49 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %48, align 1, !tbaa !10
  %50 = mul i64 2, %46
  %51 = add i64 %50, 1
  %52 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm8EEixEm(%"struct.std::__1::array.1"* noundef nonnull align 1 dereferenceable(32) %3, i64 noundef %51) #1
  %53 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %52, align 1, !tbaa !10
  %54 = call noundef __zkllvm_field_pallas_base @_ZN3nil7crypto34hashINS0_6hashes8poseidonEEENT_10block_typeES5_S5_(__zkllvm_field_pallas_base noundef %49, __zkllvm_field_pallas_base noundef %53)
  %55 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm4EEixEm(%"struct.std::__1::array.2"* noundef nonnull align 1 dereferenceable(16) %4, i64 noundef %46) #1
  store __zkllvm_field_pallas_base %54, __zkllvm_field_pallas_base* %55, align 1, !tbaa !10
  br label %56

56:                                               ; preds = %45
  %57 = add i64 %46, 1
  %58 = icmp ult i64 %57, 4
  br i1 %58, label %45, label %44, !llvm.loop !14

59:                                               ; preds = %44
  br label %61

60:                                               ; preds = %72
  br label %75

61:                                               ; preds = %59, %72
  %62 = phi i64 [ 0, %59 ], [ %73, %72 ]
  %63 = mul i64 2, %62
  %64 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm4EEixEm(%"struct.std::__1::array.2"* noundef nonnull align 1 dereferenceable(16) %4, i64 noundef %63) #1
  %65 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %64, align 1, !tbaa !10
  %66 = mul i64 2, %62
  %67 = add i64 %66, 1
  %68 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm4EEixEm(%"struct.std::__1::array.2"* noundef nonnull align 1 dereferenceable(16) %4, i64 noundef %67) #1
  %69 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %68, align 1, !tbaa !10
  %70 = call noundef __zkllvm_field_pallas_base @_ZN3nil7crypto34hashINS0_6hashes8poseidonEEENT_10block_typeES5_S5_(__zkllvm_field_pallas_base noundef %65, __zkllvm_field_pallas_base noundef %69)
  %71 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm2EEixEm(%"struct.std::__1::array.3"* noundef nonnull align 1 dereferenceable(8) %5, i64 noundef %62) #1
  store __zkllvm_field_pallas_base %70, __zkllvm_field_pallas_base* %71, align 1, !tbaa !10
  br label %72

72:                                               ; preds = %61
  %73 = add i64 %62, 1
  %74 = icmp ult i64 %73, 2
  br i1 %74, label %61, label %60, !llvm.loop !15

75:                                               ; preds = %60
  %76 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm2EEixEm(%"struct.std::__1::array.3"* noundef nonnull align 1 dereferenceable(8) %5, i64 noundef 0) #1
  %77 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %76, align 1, !tbaa !10
  %78 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm2EEixEm(%"struct.std::__1::array.3"* noundef nonnull align 1 dereferenceable(8) %5, i64 noundef 1) #1
  %79 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %78, align 1, !tbaa !10
  %80 = call noundef __zkllvm_field_pallas_base @_ZN3nil7crypto34hashINS0_6hashes8poseidonEEENT_10block_typeES5_S5_(__zkllvm_field_pallas_base noundef %77, __zkllvm_field_pallas_base noundef %79)
  %81 = bitcast %"struct.std::__1::array.3"* %5 to i8*
  call void @llvm.lifetime.end.p0i8(i64 8, i8* %81) #1
  %82 = bitcast %"struct.std::__1::array.2"* %4 to i8*
  call void @llvm.lifetime.end.p0i8(i64 16, i8* %82) #1
  %83 = bitcast %"struct.std::__1::array.1"* %3 to i8*
  call void @llvm.lifetime.end.p0i8(i64 32, i8* %83) #1
  %84 = bitcast %"struct.std::__1::array.0"* %2 to i8*
  call void @llvm.lifetime.end.p0i8(i64 64, i8* %84) #1
  ret __zkllvm_field_pallas_base %80
}

; Function Attrs: mustprogress
define linkonce_odr dso_local noundef __zkllvm_field_pallas_base @_ZN3nil7crypto34hashINS0_6hashes8poseidonEEENT_10block_typeES5_S5_(__zkllvm_field_pallas_base noundef %0, __zkllvm_field_pallas_base noundef %1) local_unnamed_addr #5 comdat {
  %3 = alloca %"struct.nil::crypto3::hashes::poseidon::process", align 1
  %4 = bitcast %"struct.nil::crypto3::hashes::poseidon::process"* %3 to i8*
  call void @llvm.lifetime.start.p0i8(i64 1, i8* %4) #1
  %5 = call noundef __zkllvm_field_pallas_base @_ZN3nil7crypto36hashes8poseidon7processclEu26__zkllvm_field_pallas_baseu26__zkllvm_field_pallas_base(%"struct.nil::crypto3::hashes::poseidon::process"* noundef nonnull align 1 dereferenceable(1) %3, __zkllvm_field_pallas_base noundef %0, __zkllvm_field_pallas_base noundef %1)
  %6 = bitcast %"struct.nil::crypto3::hashes::poseidon::process"* %3 to i8*
  call void @llvm.lifetime.end.p0i8(i64 1, i8* %6) #1
  ret __zkllvm_field_pallas_base %5
}

; Function Attrs: mustprogress nounwind
define internal fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm49EEixEm(%"struct.std::__1::array"* noundef nonnull align 1 dereferenceable(196) %0, i64 noundef %1) unnamed_addr #0 align 2 {
  %3 = getelementptr inbounds %"struct.std::__1::array", %"struct.std::__1::array"* %0, i32 0, i32 0
  %4 = getelementptr inbounds [49 x __zkllvm_field_pallas_base], [49 x __zkllvm_field_pallas_base]* %3, i64 0, i64 %1
  ret __zkllvm_field_pallas_base* %4
}

; Function Attrs: mustprogress nounwind
define internal fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm16EEixEm(%"struct.std::__1::array.0"* noundef nonnull align 1 dereferenceable(64) %0, i64 noundef %1) unnamed_addr #0 align 2 {
  %3 = getelementptr inbounds %"struct.std::__1::array.0", %"struct.std::__1::array.0"* %0, i32 0, i32 0
  %4 = getelementptr inbounds [16 x __zkllvm_field_pallas_base], [16 x __zkllvm_field_pallas_base]* %3, i64 0, i64 %1
  ret __zkllvm_field_pallas_base* %4
}

; Function Attrs: mustprogress nounwind
define internal fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm8EEixEm(%"struct.std::__1::array.1"* noundef nonnull align 1 dereferenceable(32) %0, i64 noundef %1) unnamed_addr #0 align 2 {
  %3 = getelementptr inbounds %"struct.std::__1::array.1", %"struct.std::__1::array.1"* %0, i32 0, i32 0
  %4 = getelementptr inbounds [8 x __zkllvm_field_pallas_base], [8 x __zkllvm_field_pallas_base]* %3, i64 0, i64 %1
  ret __zkllvm_field_pallas_base* %4
}

; Function Attrs: mustprogress nounwind
define internal fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm4EEixEm(%"struct.std::__1::array.2"* noundef nonnull align 1 dereferenceable(16) %0, i64 noundef %1) unnamed_addr #0 align 2 {
  %3 = getelementptr inbounds %"struct.std::__1::array.2", %"struct.std::__1::array.2"* %0, i32 0, i32 0
  %4 = getelementptr inbounds [4 x __zkllvm_field_pallas_base], [4 x __zkllvm_field_pallas_base]* %3, i64 0, i64 %1
  ret __zkllvm_field_pallas_base* %4
}

; Function Attrs: mustprogress nounwind
define internal fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm2EEixEm(%"struct.std::__1::array.3"* noundef nonnull align 1 dereferenceable(8) %0, i64 noundef %1) unnamed_addr #0 align 2 {
  %3 = getelementptr inbounds %"struct.std::__1::array.3", %"struct.std::__1::array.3"* %0, i32 0, i32 0
  %4 = getelementptr inbounds [2 x __zkllvm_field_pallas_base], [2 x __zkllvm_field_pallas_base]* %3, i64 0, i64 %1
  ret __zkllvm_field_pallas_base* %4
}

; Function Attrs: mustprogress nounwind
define linkonce_odr dso_local noundef __zkllvm_field_pallas_base @_ZN3nil7crypto36hashes8poseidon7processclEu26__zkllvm_field_pallas_baseu26__zkllvm_field_pallas_base(%"struct.nil::crypto3::hashes::poseidon::process"* noundef nonnull align 1 dereferenceable(1) %0, __zkllvm_field_pallas_base noundef %1, __zkllvm_field_pallas_base noundef %2) local_unnamed_addr #0 comdat align 2 {
  %4 = insertelement <3 x __zkllvm_field_pallas_base> <__zkllvm_field_pallas_base f0x0, __zkllvm_field_pallas_base undef, __zkllvm_field_pallas_base undef>, __zkllvm_field_pallas_base %1, i32 1
  %5 = insertelement <3 x __zkllvm_field_pallas_base> %4, __zkllvm_field_pallas_base %2, i32 2
  %6 = tail call <3 x __zkllvm_field_pallas_base> @llvm.assigner.poseidon.v3field(<3 x __zkllvm_field_pallas_base> %5)
  %7 = extractelement <3 x __zkllvm_field_pallas_base> %6, i32 2
  ret __zkllvm_field_pallas_base %7
}

; Function Attrs: nounwind
declare <3 x __zkllvm_field_pallas_base> @llvm.assigner.poseidon.v3field(<3 x __zkllvm_field_pallas_base>) #1

attributes #0 = { mustprogress nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }
attributes #1 = { nounwind }
attributes #2 = { mustprogress nounwind allocsize(0) "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }
attributes #3 = { mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #4 = { circuit mustprogress "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }
attributes #5 = { mustprogress "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }

!llvm.linker.options = !{}
!llvm.module.flags = !{!0, !1}
!llvm.ident = !{!2}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"frame-pointer", i32 2}
!2 = !{!"clang version 16.0.0 (https://github.com/NilFoundation/zkllvm-circifier.git 87213731868770cbeb419d77b635eefd2004e0fb)"}
!3 = !{!4, !4, i64 0}
!4 = !{!"long", !5, i64 0}
!5 = !{!"omnipotent char", !6, i64 0}
!6 = !{!"Simple C++ TBAA"}
!7 = distinct !{!7, !8, !9}
!8 = !{!"llvm.loop.mustprogress"}
!9 = !{!"llvm.loop.unroll.disable"}
!10 = !{!11, !11, i64 0}
!11 = !{!"__zkllvm_field_pallas_base", !5, i64 0}
!12 = distinct !{!12, !8, !9}
!13 = distinct !{!13, !8, !9}
!14 = distinct !{!14, !8, !9}
!15 = distinct !{!15, !8, !9}
