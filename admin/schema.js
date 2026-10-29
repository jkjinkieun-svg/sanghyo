/* ============================================================================
   관리자 편집 항목 정의 (schema)
   ----------------------------------------------------------------------------
   - key   : 홈페이지 HTML의 data-edit / data-edit-img / data-edit-show / data-edit-href 값
   - type  : text(한 줄) · textarea(여러 줄, **굵게** 지원) · url · toggle(표시/숨김)
             · image(이미지 업로드) · html(HTML 직접 편집)
   - 여기에 없는 data-edit 키가 HTML에 있으면 '기타 항목'으로 자동 표시됩니다.
   ============================================================================ */
(function () {
  // 반복되는 카드 필드를 만드는 도우미
  const valueCard = n => ({ title: `핵심 가치 ${n}`, fields: [
    { key: `value${n}_show`, label: '이 카드 표시', type: 'toggle' },
    { key: `value${n}_title`, label: '제목 (영문)', type: 'text' },
    { key: `value${n}_sub`, label: '부제 (한글)', type: 'text' },
    { key: `value${n}_desc`, label: '설명', type: 'textarea' }
  ]});
  const productCard = n => ({ title: `솔루션 카드 ${n}`, fields: [
    { key: `product${n}_show`, label: '이 카드 표시', type: 'toggle' },
    { key: `product${n}_image`, label: '썸네일 이미지', type: 'image', maxDim: 1600, help: '권장 1600×1000px (16:10). 비우면 기본 일러스트가 표시됩니다.' },
    { key: `product${n}_category`, label: '분류', type: 'text' },
    { key: `product${n}_title`, label: '제목', type: 'text' },
    { key: `product${n}_desc`, label: '설명', type: 'textarea' },
    { key: `product${n}_link_label`, label: '링크 문구', type: 'text' },
    { key: `product${n}_link`, label: '링크 주소', type: 'url', help: '외부 주소(https://…)는 새 창으로 열립니다. 문의 섹션은 #contact' }
  ]});
  const stepCard = n => ({ title: `${n}단계`, fields: [
    { key: `step${n}_show`, label: '이 단계 표시', type: 'toggle' },
    { key: `step${n}_num`, label: '번호', type: 'text' },
    { key: `step${n}_title`, label: '제목', type: 'text' },
    { key: `step${n}_desc`, label: '설명', type: 'textarea' }
  ]});
  const statCard = n => ({ title: `지표 ${n}`, fields: [
    { key: `stat${n}_show`, label: '이 지표 표시', type: 'toggle' },
    { key: `stat${n}_label`, label: '이름', type: 'text' },
    { key: `stat${n}_pre`, label: '값 (앞)', type: 'text' },
    { key: `stat${n}_accent`, label: '골드 강조', type: 'text' },
    { key: `stat${n}_post`, label: '값 (뒤)', type: 'text' }
  ]});

  const legalPage = (id, file, title) => ({
    id, file, title,
    groups: [{
      id: 'doc', title: '문서 내용',
      desc: '본문은 HTML로 편집합니다. 제목은 <h2>, 문단은 <p>, 목록은 <ul><li> 형식을 유지하세요.',
      fields: [
        { key: 'effective_date', label: '시행일자', type: 'text' },
        { key: 'legal_body', label: '본문 (HTML)', type: 'html' }
      ]
    }]
  });

  window.ADMIN_PAGES = [
    {
      id: 'home', file: 'index.html', title: '홈페이지',
      groups: [
        { id: 'basic', title: '회사 기본정보', desc: '헤더·연락처·푸터 등 여러 곳에 함께 반영됩니다.', fields: [
          { key: 'company_name', label: '회사명', type: 'text' },
          { key: 'company_name_en', label: '영문 회사명', type: 'text' },
          { key: 'phone', label: '전화번호', type: 'text' },
          { key: 'email', label: '이메일', type: 'text' },
          { key: 'address', label: '주소 (연락처 섹션)', type: 'text' },
          { key: 'address_short', label: '주소 (푸터)', type: 'text' },
          { key: 'ceo', label: '대표자 (푸터, 비우면 숨김)', type: 'text' },
          { key: 'biz_no', label: '사업자등록번호 (푸터, 비우면 숨김)', type: 'text' }
        ]},
        { id: 'images', title: '로고 · 대표 이미지', fields: [
          { key: 'logo', label: '로고 이미지', type: 'image', maxDim: 512, help: '정사각형 투명 PNG 권장. 비우면 기본 SVG 로고가 표시됩니다.' },
          { key: 'hero_image', label: '히어로 이미지 (첫 화면 오른쪽)', type: 'image', maxDim: 1400, help: '정사각형 권장. 비우면 로고 대형 버전이 표시됩니다.' },
          { key: 'og_image', label: 'SNS 공유 이미지 (카카오톡·페이스북 미리보기)', type: 'image', maxDim: 1200, help: '1200×630px 권장.' }
        ]},
        { id: 'seo', title: '검색 노출 (SEO)', fields: [
          { key: 'site_url', label: '사이트 주소', type: 'text', help: '예: https://www.sanghyo.com/ 또는 https://계정명.github.io/저장소/ (끝에 / 포함). 공유 이미지 주소에도 쓰입니다.' },
          { key: 'seo_title', label: '브라우저 제목', type: 'text' },
          { key: 'seo_desc', label: '검색 설명문', type: 'textarea', help: '80~150자 권장' },
          { key: 'seo_keywords', label: '키워드 (쉼표 구분)', type: 'text' },
          { key: 'og_title', label: 'SNS 공유 제목', type: 'text' },
          { key: 'og_desc', label: 'SNS 공유 설명', type: 'text' }
        ]},
        { id: 'nav', title: '메뉴', fields: [
          { key: 'nav_about', label: '회사소개 메뉴', type: 'text' },
          { key: 'nav_business', label: '사업분야 메뉴', type: 'text' },
          { key: 'nav_products', label: '솔루션 메뉴', type: 'text' },
          { key: 'nav_process', label: '진행방식 메뉴', type: 'text' },
          { key: 'nav_contact', label: '문의하기 메뉴', type: 'text' },
          { key: 'nav_cta', label: '상단 버튼', type: 'text' }
        ]},
        { id: 'hero', title: '첫 화면 (Hero)', fields: [
          { key: 'hero_title_1', label: '메인 카피 1줄 (흰색)', type: 'text' },
          { key: 'hero_title_2', label: '메인 카피 2줄 (골드)', type: 'text' },
          { key: 'hero_desc', label: '소개 문장', type: 'textarea' },
          { key: 'hero_cta1', label: '버튼 1 (골드)', type: 'text' },
          { key: 'hero_cta2', label: '버튼 2', type: 'text' }
        ], items: [statCard(1), statCard(2), statCard(3)] },
        { id: 'about', title: '회사소개', fields: [
          { key: 'about_eyebrow', label: '소제목 (영문)', type: 'text' },
          { key: 'about_title', label: '제목', type: 'textarea' },
          { key: 'about_p1', label: '본문 1', type: 'textarea' },
          { key: 'about_p2', label: '본문 2', type: 'textarea' }
        ], items: [valueCard(1), valueCard(2), valueCard(3), valueCard(4)] },
        { id: 'business', title: '사업분야', fields: [
          { key: 'biz_eyebrow', label: '소제목 (영문)', type: 'text' },
          { key: 'biz_title', label: '제목', type: 'text' },
          { key: 'biz_desc', label: '설명', type: 'textarea' }
        ], items: [
          { title: '카드 1 · 방송 SI (넓은 카드)', fields: [
            { key: 'biz1_show', label: '이 카드 표시', type: 'toggle' },
            { key: 'biz1_badge', label: '배지', type: 'text' },
            { key: 'biz1_title', label: '제목', type: 'text' },
            { key: 'biz1_desc', label: '설명', type: 'textarea' },
            { key: 'biz1_tag1', label: '태그 1 (비우면 숨김)', type: 'text' },
            { key: 'biz1_tag2', label: '태그 2', type: 'text' },
            { key: 'biz1_tag3', label: '태그 3', type: 'text' },
            { key: 'biz1_tag4', label: '태그 4', type: 'text' }
          ]},
          { title: '카드 2', fields: [
            { key: 'biz2_show', label: '이 카드 표시', type: 'toggle' },
            { key: 'biz2_badge', label: '배지', type: 'text' },
            { key: 'biz2_title', label: '제목', type: 'text' },
            { key: 'biz2_desc', label: '설명', type: 'textarea' }
          ]},
          { title: '카드 3', fields: [
            { key: 'biz3_show', label: '이 카드 표시', type: 'toggle' },
            { key: 'biz3_title', label: '제목', type: 'text' },
            { key: 'biz3_desc', label: '설명', type: 'textarea' }
          ]}
        ]},
        { id: 'products', title: '솔루션', fields: [
          { key: 'prod_eyebrow', label: '소제목 (영문)', type: 'text' },
          { key: 'prod_title', label: '제목', type: 'text' },
          { key: 'prod_desc', label: '설명', type: 'textarea' }
        ], items: [productCard(1), productCard(2), productCard(3), productCard(4)] },
        { id: 'process', title: '진행방식', fields: [
          { key: 'process_eyebrow', label: '소제목 (영문)', type: 'text' },
          { key: 'process_title', label: '제목', type: 'text' }
        ], items: [stepCard(1), stepCard(2), stepCard(3), stepCard(4)] },
        { id: 'contact', title: '문의하기', desc: '전화·이메일·주소 값은 [회사 기본정보]에서 수정합니다.', fields: [
          { key: 'contact_eyebrow', label: '소제목 (영문)', type: 'text' },
          { key: 'contact_title', label: '제목', type: 'textarea' },
          { key: 'contact_desc', label: '안내 문구', type: 'textarea' },
          { key: 'contact_phone_label', label: '전화 항목명', type: 'text' },
          { key: 'contact_email_label', label: '이메일 항목명', type: 'text' },
          { key: 'contact_address_label', label: '주소 항목명', type: 'text' }
        ]},
        { id: 'footer', title: '푸터', fields: [
          { key: 'footer_tagline', label: '소개 문구', type: 'textarea' },
          { key: 'footer_menu_title', label: '메뉴 제목', type: 'text' },
          { key: 'footer_info_title', label: '회사 정보 제목', type: 'text' },
          { key: 'copyright_name', label: '저작권 표기 이름', type: 'text' }
        ]}
      ]
    },
    legalPage('privacy', 'privacy.html', '개인정보처리방침'),
    legalPage('terms', 'terms.html', '이용약관')
  ];
})();
