/*
 * status —— 状态与诊断：堡垒机状态、撞登录的地址、登录检查结论。
 */
namespace go jmsms

/**
 * 一个反复失败登录的来源地址（jms_security_review 的一行）。
 */
struct OffendingIP {
  1: required string ip,
  2: required i32 failures,
  3: required i32 successes,
  /** 堡垒机是不是已经把这个地址拉黑了。 */
  4: required bool blocked,
}

/**
 * 堡垒机自己的登录检查结果（jms_login_asset_check 的一小块）。
 *
 * 它是堡垒机的话，不是我们的判断，所以只有它自己说得出的那几项。
 */
struct LoginCheckVerdict {
  /** 堡垒机是不是要人工复核这次登录。 */
  1: optional bool need_review,
  /** 堡垒机给的理由（它有的话）。 */
  2: optional string message,
}

/**
 * 堡垒机的状态（jms_status）。
 *
 * 这是「这个 MCP 接得对不对」的第一眼：token 能不能用、堡垒机在哪、
 * 资产有多少、连不上的有几台。
 */
struct BastionStatus {
  /** token 能不能调 API。 */
  1: required bool auth_ok,
  /** 堡垒机地址。 */
  2: required string base_url,
  /** 按平台分的资产数（探不到资产时是空表）。 */
  3: required map<string, i32> asset_by_platform,
  /** 连通性正常的资产数。 */
  4: optional i32 connectivity_ok,
  /** 连不上的资产数。 */
  5: optional i32 connectivity_err,
  /** 资产总数。 */
  6: optional i32 asset_total,
  /** 当前身份的用户名。 */
  7: optional string user,
  /** 当前身份的名字。 */
  8: optional string name,
  /** 探不到身份时的原因（比如 token 没权限）。 */
  9: optional string error,
  /** 答复的说明（如：分布只覆盖前 N 行——大资产库上 total 走的是服务器自己的计数）。 */
  10: optional string note,
}
