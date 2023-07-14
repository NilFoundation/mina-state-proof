; ModuleID = 'llvm-link'
source_filename = "llvm-link"
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
  tail call void @llvm.assigner.free(i8* %0)
  ret void
}

; Function Attrs: nounwind
declare void @llvm.assigner.free(i8*) #1

; Function Attrs: mustprogress nounwind allocsize(0)
define dso_local i8* @malloc(i64 noundef %0) local_unnamed_addr #2 {
  %2 = tail call i8* @llvm.assigner.malloc(i64 %0)
  ret i8* %2
}

; Function Attrs: nounwind
declare i8* @llvm.assigner.malloc(i64) #1

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
  %10 = getelementptr inbounds [2 x i64], [2 x i64]* %4, i64 0, i64 1
  %11 = load i64, i64* %10, align 8, !tbaa !3
  %12 = add i64 1, %11
  ret i64 %12
}

; Function Attrs: circuit mustprogress
define dso_local noundef __zkllvm_field_pallas_base @_Z20merkle_tree_poseidonNSt3__15arrayIu26__zkllvm_field_pallas_baseLm49EEE(%"struct.std::__1::array"* noundef byval(%"struct.std::__1::array") align 1 %0) local_unnamed_addr #3 {
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
  br label %10

10:                                               ; preds = %10, %1
  %11 = phi i64 [ 0, %1 ], [ %21, %10 ]
  %12 = mul i64 2, %11
  %13 = add i64 14, %12
  %14 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm49EEixEm(%"struct.std::__1::array"* noundef nonnull align 1 dereferenceable(196) %0, i64 noundef %13) #1
  %15 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %14, align 1, !tbaa !10
  %16 = add i64 %13, 1
  %17 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm49EEixEm(%"struct.std::__1::array"* noundef nonnull align 1 dereferenceable(196) %0, i64 noundef %16) #1
  %18 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %17, align 1, !tbaa !10
  %19 = call noundef __zkllvm_field_pallas_base @_ZN3nil7crypto34hashINS0_6hashes8poseidonEEENT_10block_typeES5_S5_(__zkllvm_field_pallas_base noundef %15, __zkllvm_field_pallas_base noundef %18)
  %20 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm16EEixEm(%"struct.std::__1::array.0"* noundef nonnull align 1 dereferenceable(64) %2, i64 noundef %11) #1
  store __zkllvm_field_pallas_base %19, __zkllvm_field_pallas_base* %20, align 1, !tbaa !10
  %21 = add i64 %11, 1
  %22 = icmp ult i64 %21, 16
  br i1 %22, label %10, label %23, !llvm.loop !12

23:                                               ; preds = %23, %10
  %24 = phi i64 [ %33, %23 ], [ 0, %10 ]
  %25 = mul i64 2, %24
  %26 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm16EEixEm(%"struct.std::__1::array.0"* noundef nonnull align 1 dereferenceable(64) %2, i64 noundef %25) #1
  %27 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %26, align 1, !tbaa !10
  %28 = add i64 %25, 1
  %29 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm16EEixEm(%"struct.std::__1::array.0"* noundef nonnull align 1 dereferenceable(64) %2, i64 noundef %28) #1
  %30 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %29, align 1, !tbaa !10
  %31 = call noundef __zkllvm_field_pallas_base @_ZN3nil7crypto34hashINS0_6hashes8poseidonEEENT_10block_typeES5_S5_(__zkllvm_field_pallas_base noundef %27, __zkllvm_field_pallas_base noundef %30)
  %32 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm8EEixEm(%"struct.std::__1::array.1"* noundef nonnull align 1 dereferenceable(32) %3, i64 noundef %24) #1
  store __zkllvm_field_pallas_base %31, __zkllvm_field_pallas_base* %32, align 1, !tbaa !10
  %33 = add i64 %24, 1
  %34 = icmp ult i64 %33, 8
  br i1 %34, label %23, label %35, !llvm.loop !13

35:                                               ; preds = %35, %23
  %36 = phi i64 [ %45, %35 ], [ 0, %23 ]
  %37 = mul i64 2, %36
  %38 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm8EEixEm(%"struct.std::__1::array.1"* noundef nonnull align 1 dereferenceable(32) %3, i64 noundef %37) #1
  %39 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %38, align 1, !tbaa !10
  %40 = add i64 %37, 1
  %41 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm8EEixEm(%"struct.std::__1::array.1"* noundef nonnull align 1 dereferenceable(32) %3, i64 noundef %40) #1
  %42 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %41, align 1, !tbaa !10
  %43 = call noundef __zkllvm_field_pallas_base @_ZN3nil7crypto34hashINS0_6hashes8poseidonEEENT_10block_typeES5_S5_(__zkllvm_field_pallas_base noundef %39, __zkllvm_field_pallas_base noundef %42)
  %44 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm4EEixEm(%"struct.std::__1::array.2"* noundef nonnull align 1 dereferenceable(16) %4, i64 noundef %36) #1
  store __zkllvm_field_pallas_base %43, __zkllvm_field_pallas_base* %44, align 1, !tbaa !10
  %45 = add i64 %36, 1
  %46 = icmp ult i64 %45, 4
  br i1 %46, label %35, label %53, !llvm.loop !14

47:                                               ; preds = %53
  %48 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm2EEixEm(%"struct.std::__1::array.3"* noundef nonnull align 1 dereferenceable(8) %5, i64 noundef 0) #1
  %49 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %48, align 1, !tbaa !10
  %50 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm2EEixEm(%"struct.std::__1::array.3"* noundef nonnull align 1 dereferenceable(8) %5, i64 noundef 1) #1
  %51 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %50, align 1, !tbaa !10
  %52 = call noundef __zkllvm_field_pallas_base @_ZN3nil7crypto34hashINS0_6hashes8poseidonEEENT_10block_typeES5_S5_(__zkllvm_field_pallas_base noundef %49, __zkllvm_field_pallas_base noundef %51)
  call void @llvm.lifetime.end.p0i8(i64 8, i8* %9) #1
  call void @llvm.lifetime.end.p0i8(i64 16, i8* %8) #1
  call void @llvm.lifetime.end.p0i8(i64 32, i8* %7) #1
  call void @llvm.lifetime.end.p0i8(i64 64, i8* %6) #1
  ret __zkllvm_field_pallas_base %52

53:                                               ; preds = %53, %35
  %54 = phi i64 [ %63, %53 ], [ 0, %35 ]
  %55 = mul i64 2, %54
  %56 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm4EEixEm(%"struct.std::__1::array.2"* noundef nonnull align 1 dereferenceable(16) %4, i64 noundef %55) #1
  %57 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %56, align 1, !tbaa !10
  %58 = add i64 %55, 1
  %59 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm4EEixEm(%"struct.std::__1::array.2"* noundef nonnull align 1 dereferenceable(16) %4, i64 noundef %58) #1
  %60 = load __zkllvm_field_pallas_base, __zkllvm_field_pallas_base* %59, align 1, !tbaa !10
  %61 = call noundef __zkllvm_field_pallas_base @_ZN3nil7crypto34hashINS0_6hashes8poseidonEEENT_10block_typeES5_S5_(__zkllvm_field_pallas_base noundef %57, __zkllvm_field_pallas_base noundef %60)
  %62 = call fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm2EEixEm(%"struct.std::__1::array.3"* noundef nonnull align 1 dereferenceable(8) %5, i64 noundef %54) #1
  store __zkllvm_field_pallas_base %61, __zkllvm_field_pallas_base* %62, align 1, !tbaa !10
  %63 = add i64 %54, 1
  %64 = icmp ult i64 %63, 2
  br i1 %64, label %53, label %47, !llvm.loop !15
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #4

; Function Attrs: mustprogress nounwind
define internal fastcc noundef nonnull align 1 dereferenceable(4) __zkllvm_field_pallas_base* @_ZNSt3__15arrayIu26__zkllvm_field_pallas_baseLm49EEixEm(%"struct.std::__1::array"* noundef nonnull align 1 dereferenceable(196) %0, i64 noundef %1) unnamed_addr #0 align 2 {
  %3 = getelementptr inbounds %"struct.std::__1::array", %"struct.std::__1::array"* %0, i32 0, i32 0
  %4 = getelementptr inbounds [49 x __zkllvm_field_pallas_base], [49 x __zkllvm_field_pallas_base]* %3, i64 0, i64 %1
  ret __zkllvm_field_pallas_base* %4
}

; Function Attrs: mustprogress
define linkonce_odr dso_local noundef __zkllvm_field_pallas_base @_ZN3nil7crypto34hashINS0_6hashes8poseidonEEENT_10block_typeES5_S5_(__zkllvm_field_pallas_base noundef %0, __zkllvm_field_pallas_base noundef %1) local_unnamed_addr #5 comdat {
  %3 = alloca %"struct.nil::crypto3::hashes::poseidon::process", align 1
  %4 = bitcast %"struct.nil::crypto3::hashes::poseidon::process"* %3 to i8*
  call void @llvm.lifetime.start.p0i8(i64 1, i8* %4) #1
  %5 = call noundef __zkllvm_field_pallas_base @_ZN3nil7crypto36hashes8poseidon7processclEu26__zkllvm_field_pallas_baseu26__zkllvm_field_pallas_base(%"struct.nil::crypto3::hashes::poseidon::process"* noundef nonnull align 1 dereferenceable(1) %3, __zkllvm_field_pallas_base noundef %0, __zkllvm_field_pallas_base noundef %1)
  call void @llvm.lifetime.end.p0i8(i64 1, i8* %4) #1
  ret __zkllvm_field_pallas_base %5
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

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #4

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
attributes #3 = { circuit mustprogress "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }
attributes #4 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #5 = { mustprogress "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }

!llvm.linker.options = !{}
!llvm.ident = !{!0}
!llvm.module.flags = !{!1, !2}

!0 = !{!"clang version 16.0.0 (https://github.com/NilFoundation/zkllvm-circifier.git 65a087de455b481e6d0c3b5b2e3e152097ea9bb6)"}
!1 = !{i32 1, !"wchar_size", i32 4}
!2 = !{i32 7, !"frame-pointer", i32 2}
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