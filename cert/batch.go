package cert

import (
	"sync"
	"time"
)

// BatchResult 批量操作结果
type BatchResult struct {
	Index       int           // 请求索引
	Certificate *Certificate  // 成功时的证书
	Error       error         // 失败时的错误
	Duration    time.Duration // 操作耗时
}

// CertValidation 证书验证请求
type CertValidation struct {
	CertPEM   []byte // 证书PEM数据
	MachineID string // 机器ID
}

// ValidationResult 验证结果
type ValidationResult struct {
	Index     int           // 请求索引
	Valid     bool          // 是否有效
	Error     error         // 错误信息（如果有）
	Duration  time.Duration // 验证耗时
	MachineID string        // 机器ID
}

// BatchManager 批量操作管理器
type BatchManager struct {
	auth       *Authorizer
	maxWorkers int
}

// NewBatchManager 创建批量操作管理器
func (a *Authorizer) NewBatchManager() *BatchManager {
	return &BatchManager{
		auth:       a,
		maxWorkers: 10, // 默认10个并发工作器
	}
}

// WithMaxWorkers 设置最大并发工作器数量
func (bm *BatchManager) WithMaxWorkers(workers int) *BatchManager {
	if workers > 0 {
		bm.maxWorkers = workers
	}
	return bm
}

// IssueMultipleCerts 批量签发证书
func (bm *BatchManager) IssueMultipleCerts(requests []*ClientCertRequest) []BatchResult {
	if len(requests) == 0 {
		return nil
	}

	results := make([]BatchResult, len(requests))
	jobs := make(chan int, len(requests))
	var wg sync.WaitGroup

	// 启动工作器
	workers := bm.maxWorkers
	if len(requests) < workers {
		workers = len(requests)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				start := time.Now()
				cert, err := bm.auth.IssueClientCert(requests[index])
				results[index] = BatchResult{
					Index:       index,
					Certificate: cert,
					Error:       err,
					Duration:    time.Since(start),
				}
			}
		}()
	}

	// 分发任务
	go func() {
		for i := range requests {
			jobs <- i
		}
		close(jobs)
	}()

	wg.Wait()
	return results
}

// ValidateMultipleCerts 批量验证证书
func (bm *BatchManager) ValidateMultipleCerts(validations []CertValidation) []ValidationResult {
	if len(validations) == 0 {
		return nil
	}

	results := make([]ValidationResult, len(validations))
	jobs := make(chan int, len(validations))
	var wg sync.WaitGroup

	// 启动工作器
	workers := bm.maxWorkers
	if len(validations) < workers {
		workers = len(validations)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				start := time.Now()
				val := validations[index]
				err := bm.auth.ValidateCert(val.CertPEM, val.MachineID)
				results[index] = ValidationResult{
					Index:     index,
					Valid:     err == nil,
					Error:     err,
					Duration:  time.Since(start),
					MachineID: val.MachineID,
				}
			}
		}()
	}

	// 分发任务
	go func() {
		for i := range validations {
			jobs <- i
		}
		close(jobs)
	}()

	wg.Wait()
	return results
}

// BatchIssueBuilder 批量签发构建器
type BatchIssueBuilder struct {
	requests []*ClientCertRequest
	bm       *BatchManager
}

// NewBatchIssue 创建批量签发构建器
func (a *Authorizer) NewBatchIssue() *BatchIssueBuilder {
	return &BatchIssueBuilder{
		requests: make([]*ClientCertRequest, 0),
		bm:       a.NewBatchManager(),
	}
}

// AddRequest 添加证书请求
func (bb *BatchIssueBuilder) AddRequest(req *ClientCertRequest) *BatchIssueBuilder {
	if req != nil {
		bb.requests = append(bb.requests, req)
	}
	return bb
}

// AddRequests 添加多个证书请求
func (bb *BatchIssueBuilder) AddRequests(requests ...*ClientCertRequest) *BatchIssueBuilder {
	for _, req := range requests {
		if req != nil {
			bb.requests = append(bb.requests, req)
		}
	}
	return bb
}

// WithMaxWorkers 设置并发工作器数量
func (bb *BatchIssueBuilder) WithMaxWorkers(workers int) *BatchIssueBuilder {
	bb.bm.WithMaxWorkers(workers)
	return bb
}

// Execute 执行批量签发
func (bb *BatchIssueBuilder) Execute() []BatchResult {
	return bb.bm.IssueMultipleCerts(bb.requests)
}

// BatchValidateBuilder 批量验证构建器
type BatchValidateBuilder struct {
	validations []CertValidation
	bm          *BatchManager
}

// NewBatchValidate 创建批量验证构建器
func (a *Authorizer) NewBatchValidate() *BatchValidateBuilder {
	return &BatchValidateBuilder{
		validations: make([]CertValidation, 0),
		bm:          a.NewBatchManager(),
	}
}

// AddValidation 添加验证请求
func (bv *BatchValidateBuilder) AddValidation(certPEM []byte, machineID string) *BatchValidateBuilder {
	bv.validations = append(bv.validations, CertValidation{
		CertPEM:   certPEM,
		MachineID: machineID,
	})
	return bv
}

// AddValidations 添加多个验证请求
func (bv *BatchValidateBuilder) AddValidations(validations ...CertValidation) *BatchValidateBuilder {
	bv.validations = append(bv.validations, validations...)
	return bv
}

// WithMaxWorkers 设置并发工作器数量
func (bv *BatchValidateBuilder) WithMaxWorkers(workers int) *BatchValidateBuilder {
	bv.bm.WithMaxWorkers(workers)
	return bv
}

// Execute 执行批量验证
func (bv *BatchValidateBuilder) Execute() []ValidationResult {
	return bv.bm.ValidateMultipleCerts(bv.validations)
}

// BatchStats 批量操作统计
type BatchStats struct {
	Total         int           // 总数量
	Success       int           // 成功数量
	Failed        int           // 失败数量
	TotalDuration time.Duration // 总耗时
	AvgDuration   time.Duration // 平均耗时
	MaxDuration   time.Duration // 最大耗时
	MinDuration   time.Duration // 最小耗时
}

// GetIssueStats 获取批量签发统计信息
func GetIssueStats(results []BatchResult) BatchStats {
	if len(results) == 0 {
		return BatchStats{}
	}

	stats := BatchStats{
		Total:       len(results),
		MinDuration: results[0].Duration,
	}

	for _, result := range results {
		if result.Error == nil {
			stats.Success++
		} else {
			stats.Failed++
		}

		stats.TotalDuration += result.Duration
		if result.Duration > stats.MaxDuration {
			stats.MaxDuration = result.Duration
		}
		if result.Duration < stats.MinDuration {
			stats.MinDuration = result.Duration
		}
	}

	if stats.Total > 0 {
		stats.AvgDuration = stats.TotalDuration / time.Duration(stats.Total)
	}

	return stats
}

// GetValidationStats 获取批量验证统计信息
func GetValidationStats(results []ValidationResult) BatchStats {
	if len(results) == 0 {
		return BatchStats{}
	}

	stats := BatchStats{
		Total:       len(results),
		MinDuration: results[0].Duration,
	}

	for _, result := range results {
		if result.Valid {
			stats.Success++
		} else {
			stats.Failed++
		}

		stats.TotalDuration += result.Duration
		if result.Duration > stats.MaxDuration {
			stats.MaxDuration = result.Duration
		}
		if result.Duration < stats.MinDuration {
			stats.MinDuration = result.Duration
		}
	}

	if stats.Total > 0 {
		stats.AvgDuration = stats.TotalDuration / time.Duration(stats.Total)
	}

	return stats
}
